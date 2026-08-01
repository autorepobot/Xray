package splithttp

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"net/url"
	reflect "reflect"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/hysteria/udphop"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/http2"
)

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

var (
	globalDialerMap    map[dialerConf]*XmuxManager
	globalDialerAccess sync.Mutex
)

type packetAffinityState struct {
	mu      sync.Mutex
	closed  bool
	current *XmuxLease
}

func (s *packetAffinityState) install(next *XmuxLease) (*XmuxLease, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false
	}
	if next == nil {
		return nil, true
	}
	previous := s.current
	s.current = next
	return previous, true
}

func (s *packetAffinityState) closeAdmission() *XmuxLease {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	current := s.current
	s.current = nil
	return current
}

type uploadInterruptState struct {
	mu     sync.Mutex
	closed bool
	reader *pipe.Reader
}

func (s *uploadInterruptState) install(reader *pipe.Reader) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		reader.Interrupt()
		return
	}
	s.reader = reader
	s.mu.Unlock()
}

func (s *uploadInterruptState) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	reader := s.reader
	s.reader = nil
	s.mu.Unlock()
	if reader != nil {
		reader.Interrupt()
	}
}

func getHTTPClientManager(dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*XmuxManager, DialerClient) {
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	if browser_dialer.HasBrowserDialer() && realityConfig == nil {
		return nil, &BrowserDialerClient{transportConfig: streamSettings.ProtocolSettings.(*Config)}
	}

	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*XmuxManager)
	}

	key := dialerConf{dest, streamSettings}

	xmuxManager, found := globalDialerMap[key]

	if !found {
		transportConfig := streamSettings.ProtocolSettings.(*Config)
		xmuxConfig := transportConfig.Xmux
		httpVersion := decideHTTPVersion(tls.ConfigFromStreamSettings(streamSettings), realityConfig)
		var h1PacketClient *http.Client
		xmuxManager = NewXmuxManagerForHTTPVersion(xmuxConfig, httpVersion, func() XmuxConn {
			client := createHTTPClient(dest, streamSettings)
			if httpVersion == "1.1" {
				defaultClient := client.(*DefaultDialerClient)
				if h1PacketClient == nil {
					h1PacketClient = newH1PacketClient(defaultClient.dialUploadConn)
				}
				defaultClient.packetClient = h1PacketClient
			}
			return client
		})
		if httpVersion == "1.1" {
			// Only the built-in native H1 manager owns the shared packet Transport.
			// Public/custom managers retain their previous admission behavior.
			xmuxManager.enableH1PacketDownAdmission()
		}
		globalDialerMap[key] = xmuxManager
	}

	return xmuxManager, nil
}

func decideHTTPVersion(tlsConfig *tls.Config, realityConfig *reality.Config) string {
	if realityConfig != nil {
		return "2"
	}
	if tlsConfig == nil {
		return "1.1"
	}
	if len(tlsConfig.NextProtocol) != 1 {
		return "2"
	}
	if tlsConfig.NextProtocol[0] == "http/1.1" {
		return "1.1"
	}
	if tlsConfig.NextProtocol[0] == "h3" {
		return "3"
	}
	return "2"
}

// prepareUTLSForHTTP keeps the fingerprint's extension set intact while
// making an explicitly selected H1 transport agree with the ClientHello. Most
// browser presets carry h2,http/1.1 regardless of config.NextProtos, whereas a
// no-ALPN fingerprint is a deliberate and valid way to negotiate H1.
func prepareUTLSForHTTP(conn *tls.UConn, tlsConfig *gotls.Config, httpVersion string) error {
	if httpVersion != "1.1" || tlsConfig.EncryptedClientHelloConfigList != nil {
		return nil
	}
	if err := conn.BuildHandshakeState(); err != nil {
		return err
	}
	for _, extension := range conn.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			if err := conn.BuildHandshakeState(); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func handshakeUTLSForHTTP(ctx context.Context, conn *tls.UConn, tlsConfig *gotls.Config, httpVersion string) error {
	if err := prepareUTLSForHTTP(conn, tlsConfig, httpVersion); err != nil {
		return err
	}
	return conn.HandshakeContext(ctx)
}

// h3PacketConnLifetime separates the lifetime of UDP port hopping from the
// short-lived context supplied by http3.Transport.Dial. quic-go cancels that
// context as soon as the Dial callback returns, while UdpHopPacketConn still
// needs to create replacement sockets for the lifetime of the QUIC connection.
type h3PacketConnLifetime struct {
	context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	packetConn net.PacketConn
	closed     bool
}

func newH3PacketConnLifetime(setupCtx context.Context) *h3PacketConnLifetime {
	ctx, cancel := context.WithCancel(context.WithoutCancel(setupCtx))
	return &h3PacketConnLifetime{Context: ctx, cancel: cancel}
}

func (l *h3PacketConnLifetime) setPacketConn(packetConn net.PacketConn) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = packetConn.Close()
		return
	}
	l.packetConn = packetConn
	l.mu.Unlock()
}

func (l *h3PacketConnLifetime) close() {
	l.cancel()

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	packetConn := l.packetConn
	l.packetConn = nil
	l.mu.Unlock()

	if packetConn != nil {
		_ = packetConn.Close()
	}
}

func (l *h3PacketConnLifetime) closeWhenDone(connCtx context.Context) {
	context.AfterFunc(connCtx, l.close)
}

type h3SystemDialFunc func(context.Context, net.Destination, *internet.SocketConfig) (net.Conn, error)

// h3ConnectedPacketConn adapts the connected UDP net.Conn commonly returned
// by alternative system dialers to quic-go's PacketConn contract. Calling
// UDPConn.WriteTo with an address on a connected socket fails; Write must be
// used instead, while ReadFrom can report the fixed peer address.
type h3ConnectedPacketConn struct {
	net.Conn
}

func (c *h3ConnectedPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	n, err := c.Read(payload)
	return n, c.RemoteAddr(), err
}

func (c *h3ConnectedPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return c.Write(payload)
}

func h3PacketConnFromSystemConn(conn net.Conn) (net.PacketConn, error) {
	switch c := conn.(type) {
	case *internet.PacketConnWrapper:
		return c.PacketConn, nil
	case *cnc.Connection:
		return &internet.FakePacketConn{Conn: c}, nil
	default:
		// Stable alternative system dialers commonly return *net.UDPConn
		// (or another connected net.Conn) instead of the default dialer's
		// unconnected wrapper.
		if _, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			return &h3ConnectedPacketConn{Conn: conn}, nil
		}
		return nil, errors.New("unsupported UDP system connection type ", reflect.TypeOf(conn))
	}
}

func h3RemoteUDPAddr(conn net.Conn) (*net.UDPAddr, error) {
	if c, ok := conn.(*cnc.Connection); ok {
		remoteAddr, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return nil, errors.New("unexpected tunneled UDP remote address type ", reflect.TypeOf(c.RemoteAddr()))
		}
		return &net.UDPAddr{IP: remoteAddr.IP, Port: remoteAddr.Port}, nil
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("unexpected UDP remote address type ", reflect.TypeOf(conn.RemoteAddr()))
	}
	return remoteAddr, nil
}

func (l *h3PacketConnLifetime) udpHopDialer(socketSettings *internet.SocketConfig, dialSystem h3SystemDialFunc) func(*net.UDPAddr) (net.PacketConn, error) {
	return func(addr *net.UDPAddr) (net.PacketConn, error) {
		conn, err := dialSystem(l.Context, net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)), socketSettings)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "skip hop: failed to dial to dest")
			return nil, errors.New("failed to dial UDP hop").Base(err)
		}

		packetConn, err := h3PacketConnFromSystemConn(conn)
		if err != nil {
			_ = conn.Close()
			errors.LogInfoInner(context.Background(), err, "skip hop: unsupported UDP connection")
			return nil, err
		}
		return packetConn, nil
	}
}

func createHTTPClient(dest net.Destination, streamSettings *internet.MemoryStreamConfig) DialerClient {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	httpVersion := decideHTTPVersion(tlsConfig, realityConfig)
	if httpVersion == "3" {
		dest.Network = net.Network_UDP // better to keep this line
	}

	var gotlsConfig *gotls.Config

	if tlsConfig != nil {
		gotlsConfig = tlsConfig.GetTLSConfig(tls.WithDestination(dest))
	}

	transportConfig := streamSettings.ProtocolSettings.(*Config)
	var h2Connections *rawConnRegistry
	if httpVersion == "2" {
		h2Connections = &rawConnRegistry{}
	}

	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := internet.DialSystem(ctxInner, dest, streamSettings.SocketSettings)
		if err != nil {
			return nil, err
		}

		if streamSettings.TcpmaskManager != nil {
			newConn, err := streamSettings.TcpmaskManager.WrapConnClient(conn)
			if err != nil {
				conn.Close()
				return nil, errors.New("mask err").Base(err)
			}
			conn = newConn
		}

		if realityConfig != nil {
			// REALITY intentionally leaves NextProtos unset. XHTTP selects H2 for
			// this authenticated tunnel and its server dispatches the inner H2
			// preface directly, so the outer fingerprint's ALPN is not an
			// authoritative signal and may legitimately be empty.
			wrappedConn, err := reality.UClient(conn, realityConfig, ctxInner, dest)
			if err != nil {
				conn.Close()
				return nil, err
			}
			conn = wrappedConn
		} else if gotlsConfig != nil {
			if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
				conn = tls.UClient(conn, gotlsConfig, fingerprint)
				if err := handshakeUTLSForHTTP(ctxInner, conn.(*tls.UConn), gotlsConfig, httpVersion); err != nil {
					conn.Close()
					return nil, err
				}
			} else {
				conn = tls.Client(conn, gotlsConfig)
				// DialTLSContext requires its custom dialer to return an already
				// handshaken connection. An implicit first-I/O handshake would not
				// reliably observe ctxInner (notably in x/net/http2's dial goroutine).
				if err := conn.(*tls.Conn).HandshakeContext(ctxInner); err != nil {
					conn.Close()
					return nil, err
				}
			}
		}

		if !h2Connections.add(conn) {
			return nil, errors.New("H2 transport closed during dial")
		}
		return conn, nil
	}

	var keepAlivePeriod time.Duration
	if streamSettings.ProtocolSettings.(*Config).Xmux != nil {
		keepAlivePeriod = time.Duration(streamSettings.ProtocolSettings.(*Config).Xmux.HKeepAlivePeriod) * time.Second
	}

	var transport http.RoundTripper

	if httpVersion == "3" {
		quicParams := streamSettings.QuicParams
		if quicParams == nil {
			quicParams = &internet.QuicParams{
				BbrProfile: string(bbr.ProfileStandard),
				UdpHop:     &internet.UdpHop{},
			}
		}
		udpHop := quicParams.UdpHop
		if udpHop == nil {
			// JSON configuration always creates this message, but callers using
			// MemoryStreamConfig directly are allowed to omit optional submessages.
			udpHop = &internet.UdpHop{}
		}

		quicConfig := &quic.Config{
			InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
			MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
			MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
			MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
			KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
			MaxIncomingStreams:             quicParams.MaxIncomingStreams,
			DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		}
		if quicParams.MaxIdleTimeout == 0 {
			quicConfig.MaxIdleTimeout = net.ConnIdleTimeout
		}
		if quicParams.KeepAlivePeriod == 0 {
			if keepAlivePeriod == 0 {
				quicConfig.KeepAlivePeriod = net.QuicgoH3KeepAlivePeriod
			} else if keepAlivePeriod > 0 {
				quicConfig.KeepAlivePeriod = keepAlivePeriod
			}
		}
		if quicParams.MaxIncomingStreams == 0 {
			// these two are defaults of quic-go/http3. the default of quic-go (no
			// http3) is different, so it is hardcoded here for clarity.
			// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
			quicConfig.MaxIncomingStreams = -1
		}

		transport = &http3.Transport{
			QUICConfig:      quicConfig,
			TLSClientConfig: gotlsConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
				if err := validateH3Congestion(quicParams); err != nil {
					return nil, err
				}
				var hopIntervalMin, hopIntervalMax time.Duration
				if len(udpHop.Ports) > 0 {
					var err error
					hopIntervalMin, hopIntervalMax, err = udphop.NormalizeIntervals(udpHop.IntervalMin, udpHop.IntervalMax)
					if err != nil {
						return nil, errors.New("invalid XHTTP/3 UDP hop interval").Base(err)
					}
				}

				var pktConn net.PacketConn
				var udpAddr *net.UDPAddr
				var index int
				lifetime := newH3PacketConnLifetime(ctx)

				dialDest := dest
				if len(udpHop.Ports) > 0 {
					index = rand.Intn(len(udpHop.Ports))
					dialDest.Port = net.Port(udpHop.Ports[index])
				}

				raw, err := internet.DialSystem(ctx, dialDest, streamSettings.SocketSettings)
				if err != nil {
					lifetime.close()
					return nil, errors.New("failed to dial to dest").Base(err)
				}
				pktConn, err = h3PacketConnFromSystemConn(raw)
				if err != nil {
					_ = raw.Close()
					lifetime.close()
					return nil, err
				}
				lifetime.setPacketConn(pktConn)
				udpAddr, err = h3RemoteUDPAddr(raw)
				if err != nil {
					lifetime.close()
					return nil, err
				}

				if len(udpHop.Ports) > 0 {
					pktConn = udphop.NewUDPHopPacketConn(udphop.ToAddrs(udpAddr.IP, udpHop.Ports), hopIntervalMin, hopIntervalMax, lifetime.udpHopDialer(streamSettings.SocketSettings, internet.DialSystem), pktConn, index)
					lifetime.setPacketConn(pktConn)
				}

				if streamSettings.UdpmaskManager != nil {
					newConn, err := streamSettings.UdpmaskManager.WrapPacketConnClient(pktConn)
					if err != nil {
						lifetime.close()
						return nil, errors.New("mask err").Base(err)
					}
					pktConn = newConn
					lifetime.setPacketConn(pktConn)
				}

				conn, err := quic.DialEarly(ctx, pktConn, udpAddr, tlsCfg, cfg)
				if err != nil {
					// DialEarly does not own a caller-supplied PacketConn. The
					// successful path transfers its lifetime to conn.Context below;
					// on handshake failure we must release it here instead.
					lifetime.close()
					return nil, err
				}
				if err := configureH3Congestion(conn, quicParams); err != nil {
					_ = conn.CloseWithError(0, "")
					lifetime.close()
					return nil, err
				}
				lifetime.closeWhenDone(conn.Context())

				return conn, nil
			},
		}
	} else if httpVersion == "2" {
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.ChromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		transport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	} else {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}

		transport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: net.ConnIdleTimeout,
			// chunked transfer download with KeepAlives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
	}

	client := &DefaultDialerClient{
		transportConfig: transportConfig,
		client:          newHTTPClient(transport),
		h2Connections:   h2Connections,
		httpVersion:     httpVersion,
		dialUploadConn:  dialContext,
	}

	return client
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	// The dial context can be short-lived, but it must still cancel setup. Bridge
	// it into an independently owned session context until the connection is
	// committed, then detach the returned logical connection from the caller.
	// A separate watchdog keeps cancelable network and browser setup from waiting
	// forever when the caller supplied no deadline; it is stopped before a
	// successful long-lived session is returned.
	dialCtx := ctx
	if err := dialCtx.Err(); err != nil {
		return nil, err
	}
	sessionCtx, sessionCancel := context.WithCancel(context.WithoutCancel(dialCtx))
	stopSetupCancellation := context.AfterFunc(dialCtx, sessionCancel)
	defer stopSetupCancellation()
	ctx = sessionCtx
	committed := false
	var setupMu sync.Mutex
	var setupTerminalErr error
	setupError := func(err error) error {
		// sessionCtx deliberately has no deadline so it can outlive a successful
		// Dial. While setup is still in progress, preserve the caller's exact
		// cancellation reason and any terminal stream failure instead of leaking
		// the bridge's context.Canceled.
		if dialErr := dialCtx.Err(); dialErr != nil {
			return dialErr
		}
		setupMu.Lock()
		terminalErr := setupTerminalErr
		setupMu.Unlock()
		if terminalErr != nil {
			return terminalErr
		}
		return err
	}
	recordTerminalError := func(err error) {
		if err == nil {
			return
		}
		setupMu.Lock()
		if setupTerminalErr == nil {
			setupTerminalErr = err
		}
		setupMu.Unlock()
	}
	setupWatchdog := time.AfterFunc(net.ConnIdleTimeout, func() {
		setupMu.Lock()
		if committed {
			setupMu.Unlock()
			return
		}
		if setupTerminalErr == nil {
			setupTerminalErr = context.DeadlineExceeded
		}
		setupMu.Unlock()
		sessionCancel()
	})
	commitSetup := func() error {
		setupMu.Lock()
		defer setupMu.Unlock()
		if err := dialCtx.Err(); err != nil {
			return err
		}
		if setupTerminalErr != nil {
			return setupTerminalErr
		}
		stopSetupCancellation()
		if err := dialCtx.Err(); err != nil {
			return err
		}
		if err := sessionCtx.Err(); err != nil {
			return err
		}
		committed = true
		setupWatchdog.Stop()
		return nil
	}
	var releaseOnce sync.Once
	var xmuxLease, xmuxLease2 *XmuxLease
	var h1PacketDownLease *h1PacketDownLease
	var packetAffinity packetAffinityState
	var uploadInterrupt uploadInterruptState
	releaseResources := func() {
		releaseOnce.Do(func() {
			// Close the affinity admission gate before canceling the session. A
			// concurrent packet rotation that already acquired a pin will observe
			// this flag, release that pin itself, and stop before posting.
			affinity := packetAffinity.closeAdmission()
			sessionCancel()
			// Wake a packet uploader only after cancellation is visible so it cannot
			// consume another request budget in the terminal-cleanup window.
			uploadInterrupt.close()
			// Release packet-down admission before transport cleanup. A retired
			// transport Close may block, but it must not prevent the next queued H1
			// packet-up session from entering its manager's five long-GET slots.
			h1PacketDownLease.Release()
			releaseXmuxLeasesAsync(affinity, xmuxLease, xmuxLease2)
		})
	}
	defer func() {
		setupWatchdog.Stop()
		setupMu.Lock()
		isCommitted := committed
		setupMu.Unlock()
		if !isCommitted {
			releaseResources()
		}
	}()

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	httpVersion := decideHTTPVersion(tlsConfig, realityConfig)
	if httpVersion == "3" {
		dest.Network = net.Network_UDP
	}

	transportConfiguration := streamSettings.ProtocolSettings.(*Config)
	xmuxManager, httpClient := getHTTPClientManager(dest, streamSettings)
	var requestURL url.URL

	if tlsConfig != nil || realityConfig != nil {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" && tlsConfig != nil {
		requestURL.Host = tlsConfig.ServerName
	}
	if requestURL.Host == "" && realityConfig != nil {
		requestURL.Host = realityConfig.ServerName
	}
	if requestURL.Host == "" {
		requestURL.Host = dest.Address.String()
	}
	if _, isBrowser := httpClient.(*BrowserDialerClient); isBrowser {
		// For Browser Dialer's optimized IP and non-standard port
		if !(requestURL.Scheme == "http" && dest.Port == 80) && !(requestURL.Scheme == "https" && dest.Port == 443) {
			requestURL.Host += ":" + dest.Port.String()
		}
	}

	requestURL.Path = transportConfiguration.GetNormalizedPath()
	requestURL.RawQuery = transportConfiguration.GetNormalizedQuery()

	mode := transportConfiguration.Mode
	if mode == "" || mode == "auto" {
		mode = "packet-up"
		if realityConfig != nil {
			mode = "stream-one"
			if transportConfiguration.DownloadSettings != nil {
				mode = "stream-up"
			}
		}
	}

	sessionId := ""
	if mode != "stream-one" {
		sessionId = transportConfiguration.GenerateSessionID()
	}

	errors.LogInfo(ctx, fmt.Sprintf("XHTTP is dialing to %s, mode %s, HTTP version %s, host %s", dest, mode, httpVersion, requestURL.Host))

	requestURL2 := requestURL
	httpClient2 := httpClient
	xmuxManager2 := xmuxManager
	if transportConfiguration.DownloadSettings != nil {
		globalDialerAccess.Lock()
		if streamSettings.DownloadSettings == nil {
			memory, conversionErr := internet.ToMemoryStreamConfig(transportConfiguration.DownloadSettings)
			if conversionErr != nil {
				globalDialerAccess.Unlock()
				return nil, errors.New("failed to parse XHTTP downloadSettings").Base(conversionErr)
			}
			if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.Penetrate {
				memory.SocketSettings = streamSettings.SocketSettings
			}
			streamSettings.DownloadSettings = memory
		}
		memory2 := streamSettings.DownloadSettings
		globalDialerAccess.Unlock()
		if memory2 == nil || memory2.Destination == nil {
			return nil, errors.New("XHTTP downloadSettings requires an address and port")
		}
		if memory2.Destination.Port == 0 {
			return nil, errors.New("XHTTP downloadSettings requires a non-zero port")
		}
		config2, ok := memory2.ProtocolSettings.(*Config)
		if !ok {
			return nil, errors.New("XHTTP downloadSettings must use the XHTTP transport, got ", memory2.ProtocolName)
		}
		dest2 := *memory2.Destination
		tlsConfig2 := tls.ConfigFromStreamSettings(memory2)
		realityConfig2 := reality.ConfigFromStreamSettings(memory2)
		httpVersion2 := decideHTTPVersion(tlsConfig2, realityConfig2)
		if httpVersion2 == "3" {
			dest2.Network = net.Network_UDP
		}
		if tlsConfig2 != nil || realityConfig2 != nil {
			requestURL2.Scheme = "https"
		} else {
			requestURL2.Scheme = "http"
		}
		xmuxManager2, httpClient2 = getHTTPClientManager(dest2, memory2)
		requestURL2.Host = config2.Host
		if requestURL2.Host == "" && tlsConfig2 != nil {
			requestURL2.Host = tlsConfig2.ServerName
		}
		if requestURL2.Host == "" && realityConfig2 != nil {
			requestURL2.Host = realityConfig2.ServerName
		}
		if requestURL2.Host == "" {
			requestURL2.Host = dest2.Address.String()
		}
		if _, isBrowser := httpClient2.(*BrowserDialerClient); isBrowser {
			// For Browser Dialer's optimized IP and non-standard port
			if !(requestURL2.Scheme == "http" && dest2.Port == 80) && !(requestURL2.Scheme == "https" && dest2.Port == 443) {
				requestURL2.Host += ":" + dest2.Port.String()
			}
		}
		requestURL2.Path = config2.GetNormalizedPath()
		requestURL2.RawQuery = config2.GetNormalizedQuery()
		errors.LogInfo(ctx, fmt.Sprintf("XHTTP is downloading from %s, mode %s, HTTP version %s, host %s", dest2, "stream-down", httpVersion2, requestURL2.Host))
	}

	// A normal browser H1 socket group has six physical connections. packet-up
	// needs at least one of them to remain available for finite uplink requests;
	// otherwise six long stream-down requests can permanently self-deadlock it.
	// Acquire before XMUX request/session accounting so a canceled queued Dial
	// does not consume hMaxRequestTimes or inflate scheduler load.
	useH1PacketPool := mode == "packet-up" &&
		transportConfiguration.DownloadSettings == nil &&
		httpVersion == "1.1" &&
		xmuxManager != nil &&
		xmuxManager2 == xmuxManager &&
		xmuxManager.hasH1PacketDownAdmission()
	if useH1PacketPool {
		var admissionErr error
		h1PacketDownLease, admissionErr = xmuxManager2.acquireH1PacketDown(ctx)
		if admissionErr != nil {
			return nil, errors.New("H1 packet-down admission canceled").Base(setupError(admissionErr))
		}
	}

	// Reserve the request budget together with Running so concurrent Dials
	// cannot all pass the same hMaxRequestTimes check and drive it negative.
	mainInitialRequests := int32(0)
	switch mode {
	case "stream-one":
		mainInitialRequests = 1
	case "stream-up":
		mainInitialRequests = 1
		if xmuxManager != nil && xmuxManager2 == xmuxManager {
			mainInitialRequests = 2
		}
	default: // packet-up has an initial stream-down on the same manager only
		if xmuxManager != nil && xmuxManager2 == xmuxManager {
			mainInitialRequests = 1
		}
	}
	if xmuxManager != nil {
		xmuxLease = xmuxManager.AcquireSessionWithRequests(ctx, mainInitialRequests)
		if xmuxLease == nil {
			return nil, errors.New("XMUX session acquisition canceled").Base(setupError(ctx.Err()))
		}
		httpClient = xmuxLease.Client().XmuxConn.(DialerClient)
	}
	if mode != "stream-one" && xmuxManager2 != nil {
		if xmuxManager2 == xmuxManager {
			xmuxLease2 = xmuxLease
			httpClient2 = httpClient
		} else {
			xmuxLease2 = xmuxManager2.AcquireSessionWithRequests(ctx, 1)
			if xmuxLease2 == nil {
				return nil, errors.New("download XMUX session acquisition canceled").Base(setupError(ctx.Err()))
			}
			httpClient2 = xmuxLease2.Client().XmuxConn.(DialerClient)
		}
	}

	onTerminalError := func(lease *XmuxLease) func(error) {
		return func(err error) {
			recordTerminalError(err)
			if lease != nil && lease.Client().XmuxConn.IsClosed() {
				lease.Retire()
			}
			releaseResources()
		}
	}
	mainTerminalError := onTerminalError(xmuxLease)
	downTerminalError := onTerminalError(xmuxLease2)

	reader, writer := io.Pipe()
	conn := splitConn{
		writer:  writer,
		onClose: releaseResources,
	}

	var err error
	if mode == "stream-one" {
		requestURL.Path = transportConfiguration.GetNormalizedPath()
		conn.reader, conn.remoteAddr, conn.localAddr, err = openStreamWithTerminal(httpClient, ctx, requestURL.String(), sessionId, reader, false, mainTerminalError)
		if err != nil {
			common.Close(reader)
			common.Close(writer)
			common.Close(conn.reader)
			return nil, setupError(err)
		}
		if err := commitSetup(); err != nil {
			common.Close(reader)
			common.Close(writer)
			common.Close(conn.reader)
			return nil, errors.New("XHTTP stream terminated during setup").Base(err)
		}
		return stat.Connection(&conn), nil
	} else { // stream-down
		if useH1PacketPool {
			conn.reader, conn.remoteAddr, conn.localAddr, err = openH1PacketDownWithTerminal(httpClient2, ctx, requestURL2.String(), sessionId, downTerminalError)
		} else {
			conn.reader, conn.remoteAddr, conn.localAddr, err = openStreamWithTerminal(httpClient2, ctx, requestURL2.String(), sessionId, nil, false, downTerminalError)
		}
		if err != nil {
			common.Close(reader)
			common.Close(writer)
			common.Close(conn.reader)
			return nil, setupError(err)
		}
	}
	if mode == "stream-up" {
		_, _, _, err = openStreamWithTerminal(httpClient, ctx, requestURL.String(), sessionId, reader, true, mainTerminalError)
		if err != nil {
			common.Close(reader)
			common.Close(writer)
			common.Close(conn.reader)
			return nil, setupError(err)
		}
		if err := commitSetup(); err != nil {
			common.Close(reader)
			common.Close(writer)
			common.Close(conn.reader)
			return nil, errors.New("XHTTP stream terminated during setup").Base(err)
		}
		return stat.Connection(&conn), nil
	}

	scMaxEachPostBytes := transportConfiguration.GetNormalizedScMaxEachPostBytes()
	scMinPostsIntervalMs := transportConfiguration.GetNormalizedScMinPostsIntervalMs()

	if scMaxEachPostBytes.From <= 0 {
		return nil, errors.New("scMaxEachPostBytes must be greater than 0")
	}

	maxUploadSize := scMaxEachPostBytes.rand()
	// WithSizeLimit(0) will still allow single bytes to pass, and a lot of
	// code relies on this behavior. Subtract 1 so that together with
	// uploadWriter wrapper, exact size limits can be enforced
	// uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - 1))
	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(max(0, maxUploadSize-buf.Size)))
	uploadInterrupt.install(uploadPipeReader)

	conn.writer = uploadWriter{
		uploadPipeWriter,
		maxUploadSize,
	}

	go func() {
		var seq int64
		var lastWrite time.Time

		dynamicHTTPClient := httpClient
		var dynamicXmuxClient *XmuxClient
		if xmuxLease != nil {
			dynamicXmuxClient = xmuxLease.Client()
		}
		for {
			// by offloading the uploads into a buffered pipe, multiple conn.Write
			// calls get automatically batched together into larger POST requests.
			// without batching, bandwidth is extremely limited.
			remainder, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				buf.ReleaseMulti(remainder)
				break
			}

			doSplit := atomic.Bool{}
			for doSplit.Store(true); doSplit.Load(); {
				if ctx.Err() != nil {
					buf.ReleaseMulti(remainder)
					return
				}
				var chunk buf.MultiBuffer
				remainder, chunk = buf.SplitSize(remainder, maxUploadSize)
				if chunk.IsEmpty() {
					break
				}

				wroteRequest := done.New()

				ctx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
					WroteRequest: func(info httptrace.WroteRequestInfo) {
						if info.Err == nil {
							wroteRequest.Close()
						}
					},
				})

				seqStr := strconv.FormatInt(seq, 10)
				seq += 1

				if scMinPostsIntervalMs.From > 0 {
					delay := time.Duration(scMinPostsIntervalMs.rand())*time.Millisecond - time.Since(lastWrite)
					if delay > 0 {
						timer := time.NewTimer(delay)
						select {
						case <-timer.C:
						case <-ctx.Done():
							timer.Stop()
							buf.ReleaseMulti(chunk)
							buf.ReleaseMulti(remainder)
							return
						}
					}
				}

				lastWrite = time.Now()

				var requestLease, nextAffinity, previousAffinity *XmuxLease
				if xmuxManager != nil {
					requestLease, nextAffinity = xmuxManager.borrowPacketWithAffinity(ctx, dynamicXmuxClient)
					if requestLease == nil {
						buf.ReleaseMulti(chunk)
						buf.ReleaseMulti(remainder)
						return
					}
					var installed bool
					previousAffinity, installed = packetAffinity.install(nextAffinity)
					if !installed {
						nextAffinity.Release()
						requestLease.Release()
						buf.ReleaseMulti(chunk)
						buf.ReleaseMulti(remainder)
						return
					}
					dynamicXmuxClient = requestLease.Client()
					dynamicHTTPClient = dynamicXmuxClient.XmuxConn.(DialerClient)
					// Start the replacement request before retiring the old affinity.
					// Its Close may be slow (notably for H3), while the new request and
					// lease no longer depend on that transport.
				}

				go func(requestCtx context.Context, hClient DialerClient, lease *XmuxLease, packet buf.MultiBuffer) {
					if lease != nil {
						defer lease.Release()
					}
					err := hClient.PostPacket(
						requestCtx,
						requestURL.String(),
						sessionId,
						seqStr,
						packet,
					)
					if err != nil {
						// Publish failure and stop future pipe reads before waking the
						// producer. Otherwise it can observe the write acknowledgement
						// first and launch another chunk or buffered batch.
						doSplit.Store(false)
						uploadPipeReader.Interrupt()
					}
					// Wake the producer before terminal cleanup: cleanup may close a
					// transport and is intentionally allowed to apply bounded backpressure.
					wroteRequest.Close()
					if err != nil {
						recordTerminalError(err)
						if lease != nil && hClient.IsClosed() {
							lease.Retire()
						}
						errors.LogInfoInner(requestCtx, err, "failed to send upload")
						releaseResources()
					}
				}(ctx, dynamicHTTPClient, requestLease, chunk)

				if previousAffinity != nil {
					previousAffinity.releaseAsync()
				}

				if _, ok := dynamicHTTPClient.(*DefaultDialerClient); ok {
					<-wroteRequest.Wait()
				}
			}
			buf.ReleaseMulti(remainder)
		}
	}()

	if err := commitSetup(); err != nil {
		common.Close(reader)
		common.Close(writer)
		common.Close(conn.reader)
		return nil, errors.New("XHTTP stream terminated during setup").Base(err)
	}
	return stat.Connection(&conn), nil
}

// A wrapper around pipe that ensures the size limit is exactly honored.
//
// The MultiBuffer pipe accepts any single WriteMultiBuffer call even if that
// single MultiBuffer exceeds the size limit, and then starts blocking on the
// next WriteMultiBuffer call. This means that ReadMultiBuffer can return more
// bytes than the size limit. We work around this by splitting a potentially
// too large write up into multiple.
type uploadWriter struct {
	*pipe.Writer
	maxLen int32
}

func (w uploadWriter) Write(b []byte) (int, error) {
	/*
		capacity := int(w.maxLen - w.Len())
		if capacity > 0 && capacity < len(b) {
			b = b[:capacity]
		}
	*/

	buffer := buf.MultiBufferContainer{}
	common.Must2(buffer.Write(b))

	var writed int
	for i, buff := range buffer.MultiBuffer {
		length := int(buff.Len())
		err := w.WriteMultiBuffer(buf.MultiBuffer{buff})
		if err != nil {
			// pipe.Writer owns and releases the failed item; the items not yet
			// handed to it are still ours.
			buf.ReleaseMulti(buffer.MultiBuffer[i+1:])
			return writed, err
		}
		// Ownership transfers to the pipe on success; the reader may release the
		// buffer immediately, so do not inspect it after WriteMultiBuffer.
		writed += length
	}
	return writed, nil
}
