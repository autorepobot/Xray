package splithttp

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type requestHandler struct {
	config         *Config
	host           string
	path           string
	ln             *Listener
	sessionMu      *sync.Mutex
	sessions       sync.Map
	localAddr      net.Addr
	socketSettings *internet.SocketConfig
}

type httpSession struct {
	uploadQueue *uploadQueue
	// for as long as the GET request is not opened by the client, this will be
	// open ("undone"), and the session may be expired within a certain TTL.
	// after the client connects, this becomes "done" and the session lives as
	// long as the GET request.
	isFullyConnected *done.Instance
}

const sessionReapTimeout = 30 * time.Second

func (h *requestHandler) connectSession(sessionId string, session *httpSession) bool {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	current, ok := h.sessions.Load(sessionId)
	if !ok || current != session || session.isFullyConnected.Done() {
		return false
	}
	session.isFullyConnected.Close()
	return true
}

func (h *requestHandler) reapSessionIfUnconnected(sessionId string, session *httpSession) bool {
	// The timer and the GET-side signal may both be ready when this goroutine is
	// finally scheduled. Serialize the state check and map deletion with the
	// GET-side transition so neither can pass a check and then lose a TOCTOU race.
	h.sessionMu.Lock()
	if session.isFullyConnected.Done() {
		h.sessionMu.Unlock()
		return false
	}
	// Do not delete a newer session that happens to reuse the same identifier.
	removed := h.sessions.CompareAndDelete(sessionId, session)
	h.sessionMu.Unlock()
	if removed {
		session.uploadQueue.Close()
	}
	return removed
}

func (h *requestHandler) upsertSession(sessionId string) *httpSession {
	// fast path
	currentSessionAny, ok := h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	// slow path
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	currentSessionAny, ok = h.sessions.Load(sessionId)
	if ok {
		return currentSessionAny.(*httpSession)
	}

	s := &httpSession{
		uploadQueue:      NewUploadQueue(h.ln.config.GetNormalizedScMaxBufferedPosts()),
		isFullyConnected: done.New(),
	}

	h.sessions.Store(sessionId, s)

	go func() {
		timer := time.NewTimer(sessionReapTimeout)
		defer timer.Stop()
		select {
		case <-s.isFullyConnected.Wait():
		case <-timer.C:
			h.reapSessionIfUnconnected(sessionId, s)
		}
	}()

	return s
}

func (h *requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if len(h.host) > 0 && !internet.IsValidHTTPHost(request.Host, h.host) {
		errors.LogInfo(context.Background(), "failed to validate host, request:", request.Host, ", config:", h.host)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	if !strings.HasPrefix(request.URL.Path, h.path) {
		errors.LogInfo(context.Background(), "failed to validate path, request:", request.URL.Path, ", config:", h.path)
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	h.config.WriteResponseHeader(writer, request.Method, request.Header)
	length := int(h.config.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if h.config.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: h.config.XPaddingPlacement,
			Key:       h.config.XPaddingKey,
			Header:    h.config.XPaddingHeader,
		}
		config.Method = PaddingMethod(h.config.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementHeader,
			Header:    "X-Padding",
		}
	}

	h.config.ApplyXPaddingToResponse(writer, config)

	if request.Method == "OPTIONS" {
		writer.WriteHeader(http.StatusOK)
		return
	}

	/*
		clientVer := []int{0, 0, 0}
		x_version := strings.Split(request.URL.Query().Get("x_version"), ".")
		for j := 0; j < 3 && len(x_version) > j; j++ {
			clientVer[j], _ = strconv.Atoi(x_version[j])
		}
	*/

	validRange := h.config.GetNormalizedXPaddingBytes()
	paddingValue, paddingPlacement := h.config.ExtractXPaddingFromRequest(request, h.config.XPaddingObfsMode)

	if !h.config.IsPaddingValid(paddingValue, validRange.From, validRange.To, PaddingMethod(h.config.XPaddingMethod)) {
		errors.LogInfo(context.Background(), "invalid padding ("+paddingPlacement+") length:", int32(len(paddingValue)))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	obfsPaddingAccepted := h.config.XPaddingObfsMode && paddingValue != ""

	sessionId, seqStr := h.config.ExtractMetaFromRequest(request, h.path)

	if sessionId == "" && h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "stream-one" && h.config.Mode != "stream-up" {
		errors.LogInfo(context.Background(), "stream-one mode is not allowed")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	var remoteAddr net.Addr
	var err error
	remoteAddr, err = net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err != nil {
		remoteAddr = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}
	if request.ProtoMajor == 3 {
		remoteAddr = &net.UDPAddr{
			IP:   remoteAddr.(*net.TCPAddr).IP,
			Port: remoteAddr.(*net.TCPAddr).Port,
		}
	}
	var trustedXFF []string
	if h.socketSettings != nil {
		trustedXFF = h.socketSettings.TrustedXForwardedFor
	}
	remoteAddr = http_proto.ApplyTrustedXForwardedFor(request.Header, trustedXFF, remoteAddr)

	var currentSession *httpSession
	if sessionId != "" {
		currentSession = h.upsertSession(sessionId)
	}
	scMaxEachPostBytes := int(h.ln.config.GetNormalizedScMaxEachPostBytes().To)
	isUplinkRequest := false

	switch request.Method {
	case "GET":
		isUplinkRequest = seqStr != ""
	default:
		isUplinkRequest = true
	}

	uplinkDataKey := h.config.UplinkDataKey

	if isUplinkRequest && sessionId != "" { // stream-up, packet-up
		if seqStr == "" {
			if h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "stream-up" {
				errors.LogInfo(context.Background(), "stream-up mode is not allowed")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			httpSC := &httpServerConn{
				Instance:       done.New(),
				Reader:         request.Body,
				ResponseWriter: writer,
			}
			err = currentSession.uploadQueue.Push(Packet{
				Reader: httpSC,
			})
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to upload (PushReader)")
				writer.WriteHeader(http.StatusConflict)
			} else {
				writer.Header().Set("X-Accel-Buffering", "no")
				writer.Header().Set("Cache-Control", "no-store")
				writer.WriteHeader(http.StatusOK)
				scStreamUpServerSecs := h.config.GetNormalizedScStreamUpServerSecs()
				hasLegacyRefererCompatMarker := request.Header.Get("Referer") != ""
				if (hasLegacyRefererCompatMarker || obfsPaddingAccepted) && scStreamUpServerSecs.To > 0 {
					go func() {
						for {
							_, err := httpSC.Write(bytes.Repeat([]byte{'X'}, int(h.config.GetNormalizedXPaddingBytes().rand())))
							if err != nil {
								return
							}
							timer := time.NewTimer(time.Duration(scStreamUpServerSecs.rand()) * time.Second)
							select {
							case <-timer.C:
							case <-httpSC.Wait():
								timer.Stop()
								return
							case <-request.Context().Done():
								timer.Stop()
								return
							}
						}
					}()
				}
				select {
				case <-request.Context().Done():
				case <-httpSC.Wait():
				}
			}
			httpSC.Close()
			return
		}

		if h.config.Mode != "" && h.config.Mode != "auto" && h.config.Mode != "packet-up" {
			errors.LogInfo(context.Background(), "packet-up mode is not allowed")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		dataPlacement := h.config.GetNormalizedUplinkDataPlacement()
		var headerPayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementHeader {
			var headerPayloadChunks []string
			for i := 0; true; i++ {
				chunk := request.Header.Get(fmt.Sprintf("%s-%d", uplinkDataKey, i))
				if chunk == "" {
					break
				}
				headerPayloadChunks = append(headerPayloadChunks, chunk)
			}
			headerPayloadEncoded := strings.Join(headerPayloadChunks, "")
			headerPayload, err = base64.RawURLEncoding.DecodeString(headerPayloadEncoded)
			if err != nil {
				errors.LogInfo(context.Background(), "Invalid base64 in header's payload: ", err.Error())
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		var cookiePayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementCookie {
			var cookiePayloadChunks []string
			for i := 0; true; i++ {
				cookieName := fmt.Sprintf("%s_%d", uplinkDataKey, i)
				if c, _ := request.Cookie(cookieName); c != nil {
					cookiePayloadChunks = append(cookiePayloadChunks, c.Value)
				} else {
					break
				}
			}
			cookiePayloadEncoded := strings.Join(cookiePayloadChunks, "")
			cookiePayload, err = base64.RawURLEncoding.DecodeString(cookiePayloadEncoded)
			if err != nil {
				errors.LogInfo(context.Background(), "Invalid base64 in cookies' payload: ", err.Error())
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		var bodyPayload []byte
		if dataPlacement == PlacementAuto || dataPlacement == PlacementBody {
			var readErr error
			if request.ContentLength > int64(scMaxEachPostBytes) {
				errors.LogInfo(context.Background(), "Too large upload. scMaxEachPostBytes is set to ", scMaxEachPostBytes, "but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.")
				writer.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			if request.ContentLength > 0 {
				bodyPayload = make([]byte, request.ContentLength)
				_, readErr = io.ReadFull(request.Body, bodyPayload)
			} else {
				bodyPayload, readErr = buf.ReadAllToBytes(io.LimitReader(request.Body, int64(scMaxEachPostBytes)+1))
			}
			if readErr != nil {
				errors.LogInfoInner(context.Background(), readErr, "failed to read body payload")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		var payload []byte
		switch dataPlacement {
		case PlacementHeader:
			payload = headerPayload
		case PlacementCookie:
			payload = cookiePayload
		case PlacementBody:
			payload = bodyPayload
		case PlacementAuto:
			payload = slices.Concat(headerPayload, cookiePayload, bodyPayload)
		}

		if len(payload) > scMaxEachPostBytes {
			errors.LogInfo(context.Background(), "Too large upload. scMaxEachPostBytes is set to ", scMaxEachPostBytes, "but request size exceed it. Adjust scMaxEachPostBytes on the server to be at least as large as client.")
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}

		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (ParseUint)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = currentSession.uploadQueue.Push(Packet{
			Payload: payload,
			Seq:     seq,
		})
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to upload (PushPayload)")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		if len(bodyPayload) == 0 {
			// Methods without a body are usually cached by default.
			writer.Header().Set("Cache-Control", "no-store")
		}

		writer.WriteHeader(http.StatusOK)
	} else if request.Method == "GET" || sessionId == "" { // stream-down, stream-one
		if sessionId != "" {
			// after GET is done, the connection is finished. disable automatic
			// session reaping, and handle it in defer
			if !h.connectSession(sessionId, currentSession) {
				errors.LogInfo(context.Background(), "session is already connected or expired")
				writer.WriteHeader(http.StatusConflict)
				return
			}
			defer h.sessions.CompareAndDelete(sessionId, currentSession)
		}

		// magic header instructs nginx + apache to not buffer response body
		writer.Header().Set("X-Accel-Buffering", "no")
		// A web-compliant header telling all middleboxes to disable caching.
		// Should be able to prevent overloading the cache, or stop CDNs from
		// teeing the response stream into their cache, causing slowdowns.
		writer.Header().Set("Cache-Control", "no-store")

		if !h.config.NoSSEHeader {
			// magic header to make the HTTP middle box consider this as SSE to disable buffer
			writer.Header().Set("Content-Type", "text/event-stream")
		}

		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()

		httpSC := &httpServerConn{
			Instance:       done.New(),
			Reader:         request.Body,
			ResponseWriter: writer,
		}
		localAddr := h.localAddr
		if la, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && la != nil {
			localAddr = la
		}
		conn := splitConn{
			writer:     httpSC,
			reader:     httpSC,
			remoteAddr: remoteAddr,
			localAddr:  localAddr,
		}
		if sessionId != "" { // if not stream-one
			conn.reader = currentSession.uploadQueue
		}

		h.ln.addConn(stat.Connection(&conn))

		// "A ResponseWriter may not be used after [Handler.ServeHTTP] has returned."
		select {
		case <-request.Context().Done():
		case <-httpSC.Wait():
		}

		conn.Close()
	} else {
		errors.LogInfo(context.Background(), "unsupported method: ", request.Method)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type httpServerConn struct {
	sync.Mutex
	*done.Instance
	io.Reader // no need to Close request.Body
	http.ResponseWriter
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	if c.Done() {
		return 0, io.ErrClosedPipe
	}
	n, err := c.ResponseWriter.Write(b)
	if err == nil {
		c.ResponseWriter.(http.Flusher).Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.Lock()
	defer c.Unlock()
	return c.Instance.Close()
}

type Listener struct {
	sync.Mutex
	server       http.Server
	h3server     *http3.Server
	listener     net.Listener
	h3listener   http3.QUICListener
	h3PacketConn net.PacketConn
	config       *Config
	addConn      internet.ConnHandler
	isH3         bool
	closeOnce    sync.Once
	closeErr     error
}

func listenQUICEarlyOwned(conn net.PacketConn, tlsConfig *gotls.Config, quicConfig *quic.Config) (http3.QUICListener, error) {
	listener, err := quic.ListenEarly(conn, tlsConfig, quicConfig)
	if err != nil {
		// A QUIC listener never takes ownership when construction fails. Keep
		// PacketConn ownership local to this helper so future callers can't miss
		// the initialization-error cleanup branch.
		_ = conn.Close()
		return nil, err
	}
	return listener, nil
}

func ListenXH(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l := &Listener{
		addConn: addConn,
	}
	l.config = streamSettings.ProtocolSettings.(*Config)
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
	}
	handler := &requestHandler{
		config:         l.config,
		host:           l.config.Host,
		path:           l.config.GetNormalizedPath(),
		ln:             l,
		sessionMu:      &sync.Mutex{},
		sessions:       sync.Map{},
		socketSettings: streamSettings.SocketSettings,
	}
	tlsConfig := getTLSConfig(streamSettings)
	l.isH3 = len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "h3"

	var err error
	if port == net.Port(0) { // unix
		l.listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UNIX domain socket for XHTTP on ", address).Base(err)
		}
		errors.LogInfo(ctx, "listening UNIX domain socket for XHTTP on ", address)
	} else if l.isH3 { // quic
		quicParams := streamSettings.QuicParams
		if quicParams == nil {
			quicParams = &internet.QuicParams{
				BbrProfile: string(bbr.ProfileStandard),
				UdpHop:     &internet.UdpHop{},
			}
		}
		if err := validateH3Congestion(quicParams); err != nil {
			return nil, err
		}

		Conn, err := internet.ListenSystemPacket(ctx, &net.UDPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UDP for XHTTP/3 on ", address, ":", port).Base(err)
		}
		if streamSettings.UdpmaskManager != nil {
			newConn, err := streamSettings.UdpmaskManager.WrapPacketConnServer(Conn)
			if err != nil {
				Conn.Close()
				return nil, errors.New("mask err").Base(err)
			}
			Conn = newConn
		}

		quicConfig := &quic.Config{
			InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
			MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
			MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
			MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams:             quicParams.MaxIncomingStreams,
			DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		}

		l.h3listener, err = listenQUICEarlyOwned(Conn, tlsConfig, quicConfig)
		if err != nil {
			return nil, errors.New("failed to listen QUIC for XHTTP/3 on ", address, ":", port).Base(err)
		}
		l.h3PacketConn = Conn
		l.h3listener = &QListener{
			QUICListener: l.h3listener,
			quicParams:   quicParams,
		}
		errors.LogInfo(ctx, "listening QUIC for XHTTP/3 on ", address, ":", port)

		handler.localAddr = l.h3listener.Addr()

		l.h3server = &http3.Server{
			Handler: handler,
			// Preserve http3.Server's 1 MiB zero-value default unless the user
			// explicitly requests a different limit. H1/H2 retain XHTTP's legacy
			// normalized 8 KiB default below.
			MaxHeaderBytes: int(l.config.ServerMaxHeaderBytes),
		}
		go func() {
			if err := l.h3server.ServeListener(l.h3listener); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
				errors.LogErrorInner(ctx, err, "failed to serve HTTP/3 for XHTTP/3")
			}
			// ServeListener doesn't own either the supplied listener or its
			// PacketConn. An unexpected Accept failure must use the same cleanup
			// path as an explicit Listener.Close.
			_ = l.Close()
		}()
	} else { // tcp
		l.listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP for XHTTP on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening TCP for XHTTP on ", address, ":", port)
	}

	if !l.isH3 && streamSettings.TcpmaskManager != nil {
		l.listener, _ = streamSettings.TcpmaskManager.WrapListener(l.listener)
	}

	// tcp/unix (h1/h2)
	if l.listener != nil {
		if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
			if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
				l.listener = gotls.NewListener(l.listener, tlsConfig)
			}
		}
		if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
			l.listener = goreality.NewListener(l.listener, config.GetREALITYConfig())
		}

		handler.localAddr = l.listener.Addr()

		// server can handle both plaintext HTTP/1.1 and h2c
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		l.server = http.Server{
			Handler:           handler,
			ReadHeaderTimeout: time.Second * 4,
			MaxHeaderBytes:    l.config.GetNormalizedServerMaxHeaderBytes(),
			Protocols:         protocols,
		}
		go func() {
			if err := l.server.Serve(l.listener); err != nil {
				errors.LogErrorInner(ctx, err, "failed to serve HTTP for XHTTP")
			}
		}()
	}

	return l, err
}

// Addr implements net.Listener.Addr().
func (ln *Listener) Addr() net.Addr {
	if ln.h3listener != nil {
		return ln.h3listener.Addr()
	}
	if ln.listener != nil {
		return ln.listener.Addr()
	}
	return nil
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	ln.closeOnce.Do(func() {
		if ln.h3server != nil || ln.h3listener != nil || ln.h3PacketConn != nil {
			// http3.Server.Close stops active requests but deliberately leaves an
			// externally supplied listener open. The QUIC listener in turn doesn't
			// own the PacketConn passed to quic.ListenEarly, so all three layers
			// must be closed, in that order, to release the UDP socket.
			var closeErrors []error
			if ln.h3server != nil {
				closeErrors = append(closeErrors, ln.h3server.Close())
			}
			if ln.h3listener != nil {
				closeErrors = append(closeErrors, ln.h3listener.Close())
			}
			if ln.h3PacketConn != nil {
				closeErrors = append(closeErrors, ln.h3PacketConn.Close())
			}
			ln.closeErr = stderrors.Join(closeErrors...)
			return
		}
		if ln.listener != nil {
			ln.closeErr = ln.listener.Close()
			return
		}
		ln.closeErr = errors.New("listener does not have an HTTP/3 server or a net.listener")
	})
	return ln.closeErr
}

func getTLSConfig(streamSettings *internet.MemoryStreamConfig) *gotls.Config {
	config := tls.ConfigFromStreamSettings(streamSettings)
	if config == nil {
		return &gotls.Config{}
	}
	return config.GetTLSConfig()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenXH))
}

type QListener struct {
	http3.QUICListener
	quicParams *internet.QuicParams
}

func (l *QListener) Accept(ctx context.Context) (*quic.Conn, error) {
	conn, err := l.QUICListener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	if err := configureH3Congestion(conn, l.quicParams); err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	return conn, nil
}
