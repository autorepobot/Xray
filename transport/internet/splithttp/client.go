package splithttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

const (
	h1MaxConnections           = 6
	h1MaxPacketDownConnections = h1MaxConnections - 1
	h1MaxIdleConnections       = h1MaxConnections
	h1PacketIdleTimeout        = 90 * time.Second
)

type redirectPolicyContextKey struct{}

func disableRedirects(request *http.Request) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), redirectPolicyContextKey{}, true))
}

func xhttpRedirectPolicy(_ *http.Request, via []*http.Request) error {
	if len(via) > 0 {
		// Upload requests are protocol operations, even when a header/cookie
		// placement uses GET. Following their redirect could drop or replay the
		// payload and turn the final 200 into a false acknowledgement.
		if disabled, _ := via[0].Context().Value(redirectPolicyContextKey{}).(bool); disabled {
			return http.ErrUseLastResponse
		}
	}
	// Match net/http's default redirect budget for compatible stream-down GETs.
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

func newHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport, CheckRedirect: xhttpRedirectPolicy}
}

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool

	// ctx, url, sessionId, body, uploadOnly
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, sessionId, seqStr, body, contentLength
	PostPacket(context.Context, string, string, string, buf.MultiBuffer) error
}

// terminalAwareDialerClient is an optional extension used by the built-in
// client. Keeping it separate preserves compatibility with existing custom
// DialerClient implementations.
type terminalAwareDialerClient interface {
	OpenStreamWithTerminal(context.Context, string, string, io.Reader, bool, func(error)) (io.ReadCloser, net.Addr, net.Addr, error)
}

// h1PacketDownDialerClient is deliberately separate from DialerClient. Dial is
// the only layer that has resolved auto mode and downloadSettings, so only it
// can safely identify a stream-down as H1 packet-up without changing native
// stream-up/stream-one or custom DialerClient behavior.
type h1PacketDownDialerClient interface {
	openH1PacketDownWithTerminal(context.Context, string, string, func(error)) (io.ReadCloser, net.Addr, net.Addr, error)
}

func openStreamWithTerminal(client DialerClient, ctx context.Context, url, sessionID string, body io.Reader, uploadOnly bool, onTerminalError func(error)) (io.ReadCloser, net.Addr, net.Addr, error) {
	if client, ok := client.(terminalAwareDialerClient); ok {
		return client.OpenStreamWithTerminal(ctx, url, sessionID, body, uploadOnly, onTerminalError)
	}
	return client.OpenStream(ctx, url, sessionID, body, uploadOnly)
}

func openH1PacketDownWithTerminal(client DialerClient, ctx context.Context, url, sessionID string, onTerminalError func(error)) (io.ReadCloser, net.Addr, net.Addr, error) {
	if client, ok := client.(h1PacketDownDialerClient); ok {
		return client.openH1PacketDownWithTerminal(ctx, url, sessionID, onTerminalError)
	}
	return openStreamWithTerminal(client, ctx, url, sessionID, nil, false, onTerminalError)
}

// implements splithttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	packetClient    *http.Client // manager-shared H1 packet-up pool; not wrapper-owned
	h2Connections   *rawConnRegistry
	closed          atomic.Bool
	closeStarted    atomic.Bool
	httpVersion     string
	dialUploadConn  func(ctxInner context.Context) (net.Conn, error)
}

// rawConnRegistry keeps the exact net.Conn returned by an H2 dialer, without
// wrapping it and hiding TLS/REALITY-specific interfaces from http2.Transport.
// CloseIdleConnections ignores a transport that still has a canceled response
// stream; the XMUX lifecycle knows when no logical owner remains, so it can
// close these raw connections deterministically at that point.
type rawConnRegistry struct {
	mu     sync.Mutex
	closed bool
	conns  []net.Conn
}

func (r *rawConnRegistry) add(conn net.Conn) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		conn.Close()
		return false
	}
	r.conns = append(r.conns, conn)
	r.mu.Unlock()
	return true
}

func (r *rawConnRegistry) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	connections := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, conn := range connections {
		// A connection may already have failed naturally. Closing it again is
		// harmless and must not turn logical connection cleanup into an error.
		_ = conn.Close()
	}
}

func newH1PacketClient(dialUploadConn func(context.Context) (net.Conn, error)) *http.Client {
	httpDialContext := func(ctx context.Context, network string, addr string) (net.Conn, error) {
		return dialUploadConn(ctx)
	}
	transport := &http.Transport{
		DialTLSContext:      httpDialContext,
		DialContext:         httpDialContext,
		ForceAttemptHTTP2:   false,
		MaxConnsPerHost:     h1MaxConnections,
		MaxIdleConns:        h1MaxConnections,
		MaxIdleConnsPerHost: h1MaxIdleConnections,
		IdleConnTimeout:     h1PacketIdleTimeout,
		// Preserve XHTTP's configured wire headers. The previous raw H1 path did
		// not inject Go's implicit "Accept-Encoding: gzip" header either.
		DisableCompression: true,
	}
	return newHTTPClient(transport)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *DefaultDialerClient) markRequestFailure() {
	// An H1 wrapper owns a pool, not one multiplexed connection. Its main
	// native streams use independent non-keepalive sockets and packet-up uses
	// the manager-shared http.Transport, which already evicts a failed connection.
	// Poisoning the wrapper here would make one socket error reject unrelated
	// logical sessions without replacing the shared packet-up pool.
	if c.httpVersion != "1.1" {
		c.closed.Store(true)
	}
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionID string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return c.OpenStreamWithTerminal(ctx, url, sessionID, body, uploadOnly, nil)
}

func (c *DefaultDialerClient) OpenStreamWithTerminal(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool, onTerminalError func(error)) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	return c.openStreamWithTerminal(ctx, url, sessionId, body, uploadOnly, onTerminalError, c.client, false)
}

func (c *DefaultDialerClient) openH1PacketDownWithTerminal(ctx context.Context, url, sessionID string, onTerminalError func(error)) (io.ReadCloser, net.Addr, net.Addr, error) {
	// Preserve custom/injected DefaultDialerClient compatibility when Dial's
	// outer settings and the supplied client disagree about HTTP version. Native
	// managers always create a matching client and initialize packetClient.
	if c.httpVersion != "1.1" {
		return c.OpenStreamWithTerminal(ctx, url, sessionID, nil, false, onTerminalError)
	}
	if c.packetClient == nil {
		return nil, nil, nil, errors.New("H1 packet pool is not initialized")
	}
	return c.openStreamWithTerminal(ctx, url, sessionID, nil, false, onTerminalError, c.packetClient, true)
}

func (c *DefaultDialerClient) openStreamWithTerminal(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool, onTerminalError func(error), requestClient *http.Client, closeAfterResponse bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	if requestClient == nil {
		return nil, nil, nil, errors.New("HTTP client is not initialized")
	}
	ready := make(chan error, 1)
	var readyOnce sync.Once
	signalReady := func(err error) {
		readyOnce.Do(func() { ready <- err })
	}
	signalConnected := func(connInfo httptrace.GotConnInfo) {
		readyOnce.Do(func() {
			// Record the same connection that releases setup. Redirects and
			// retries may invoke GotConn again after Dial starts returning; those
			// later callbacks must not race with these result addresses.
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			ready <- nil
		})
	}
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			// Preserve the upstream stream-down behavior: an intermediary may
			// buffer response headers until downstream data exists, while the
			// origin waits for uplink data that cannot start before Dial returns.
			signalConnected(connInfo)
		},
	})

	method := "GET" // stream-down
	if body != nil {
		method = c.transportConfig.GetNormalizedUplinkHTTPMethod() // stream-up/one
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to create HTTP request for "+url)
		return nil, nil, nil, err
	}
	if body != nil || uploadOnly {
		req = disableRedirects(req)
	}
	c.transportConfig.FillStreamRequest(req, sessionId, "")
	requestedGzip := false
	if closeAfterResponse {
		// The old H1 stream transport had DisableKeepAlives set globally. Keep the
		// exact per-request behavior while sharing the packet Transport so the
		// active long GET still counts against MaxConnsPerHost without becoming an
		// idle reusable socket afterwards.
		req.Close = true
		// The shared packet Transport disables implicit compression so finite uplink
		// requests retain their previous wire headers. Reproduce net/http's former
		// implicit GET behavior here, including transparent lazy decompression.
		if req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" && req.Method != http.MethodHead {
			req.Header.Set("Accept-Encoding", "gzip")
			requestedGzip = true
		}
	}

	waitReader := newWaitReadCloser()
	wrc = waitReader
	go func() {
		resp, requestErr := requestClient.Do(req)
		if requestErr != nil {
			signalReady(requestErr)
			if ctx.Err() == nil {
				// Preserve the legacy distinction: an upload-only stream failure
				// terminates its logical session but does not poison the transport.
				if !uploadOnly {
					c.markRequestFailure()
				}
				errors.LogInfoInner(ctx, requestErr, "failed to "+method+" "+url)
				if onTerminalError != nil {
					onTerminalError(requestErr)
				}
			}
			common.Close(body)
			waitReader.Close()
			return
		}
		if requestedGzip && strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			resp.Body = &lazyGzipReadCloser{body: resp.Body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			resp.Uncompressed = true
		}
		if resp.StatusCode != http.StatusOK {
			statusErr := errors.New("unexpected status ", resp.Status)
			signalReady(statusErr)
			errors.LogInfo(ctx, statusErr)
			if ctx.Err() == nil && onTerminalError != nil {
				onTerminalError(statusErr)
			}
			// This logical stream is terminal. Do not wait indefinitely to drain a
			// hostile/non-terminating error body merely to make the connection
			// reusable; cancellation and Close abort it promptly.
			resp.Body.Close()
			common.Close(body)
			waitReader.Close()
			return
		}
		// GotConn already released setup. A status failure that raced with Dial's
		// commit is still delivered through onTerminalError and tears down the
		// logical session without imposing a response-header dependency here.
		signalReady(nil)
		if uploadOnly { // stream-up
			_, copyErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			common.Close(body)
			waitReader.Close()
			terminalErr := copyErr
			if terminalErr == nil {
				terminalErr = closeErr
			}
			if terminalErr != nil && ctx.Err() == nil {
				errors.LogInfoInner(ctx, terminalErr, "failed to finish "+method+" "+url)
				if onTerminalError != nil {
					onTerminalError(terminalErr)
				}
			}
			return
		}
		if closeAfterResponse && onTerminalError != nil {
			// A remote EOF terminates the logical packet-up session just as surely as
			// a request/status failure. Without this hook the five-slot admission
			// could remain held until a caller explicitly closed an already-dead conn.
			resp.Body = &terminalReadCloser{ReadCloser: resp.Body, onTerminal: onTerminalError}
		}
		waitReader.Set(resp.Body)
	}()

	if readyErr := <-ready; readyErr != nil {
		return nil, nil, nil, readyErr
	}
	return wrc, remoteAddr, localAddr, nil
}

type terminalReadCloser struct {
	io.ReadCloser
	once       sync.Once
	onTerminal func(error)
}

func (r *terminalReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err != nil && r.onTerminal != nil {
		r.once.Do(func() { r.onTerminal(err) })
	}
	return n, err
}

// lazyGzipReadCloser mirrors net/http's lazy transparent decompression. A
// stream-down response may flush its headers before producing any body bytes;
// constructing gzip.Reader eagerly would make Dial wait for application data.
type lazyGzipReadCloser struct {
	body   io.ReadCloser
	once   sync.Once
	reader *gzip.Reader
	err    error
}

func (r *lazyGzipReadCloser) Read(p []byte) (int, error) {
	r.once.Do(func() {
		r.reader, r.err = gzip.NewReader(r.body)
	})
	if r.err != nil {
		return 0, r.err
	}
	return r.reader.Read(p)
}

func (r *lazyGzipReadCloser) Close() error {
	// gzip.Reader.Close does not close the underlying response and holds no
	// external resource. Avoid touching reader here so response Body.Close can
	// safely interrupt a concurrent first Read without racing lazy publication.
	return r.body.Close()
}

func makeReplayableBody(req *http.Request) error {
	if req.Body == nil {
		return nil
	}
	data, err := io.ReadAll(req.Body)
	closeErr := req.Body.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	req.ContentLength = int64(len(data))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	req.Body, _ = req.GetBody()
	// There is deliberately no application-level retry. With the default POST,
	// net/http uses GetBody to retry a reused connection only when no request
	// bytes were written. Explicitly idempotent methods or headers may also be
	// replayed after an ambiguous response failure; XHTTP sequence numbers make
	// those duplicates safe server-side.
	return nil
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	if c.closed.Load() {
		buf.ReleaseMulti(payload)
		return errors.New("packet upload client is closed")
	}
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		buf.ReleaseMulti(payload)
		return err
	}
	req = disableRedirects(req)
	if err := c.transportConfig.FillPacketRequest(req, sessionId, seqStr, payload); err != nil {
		common.Close(req.Body)
		return err
	}

	requestClient := c.client
	if c.httpVersion == "1.1" {
		if c.packetClient == nil {
			common.Close(req.Body)
			return errors.New("H1 packet pool is not initialized")
		}
		if err := makeReplayableBody(req); err != nil {
			return err
		}
		requestClient = c.packetClient
	}

	resp, err := requestClient.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			c.markRequestFailure()
		}
		return err
	}
	if resp.StatusCode != http.StatusOK {
		// Do not drain an error response: an untrusted peer can keep that body
		// open indefinitely and prevent the session from observing the failure.
		resp.Body.Close()
		return errors.New("bad status code:", resp.Status)
	}
	// The 200 response headers are the packet acknowledgement. Do not wait for
	// a response body: compatible servers and intermediaries may keep that
	// stream open after acknowledging the packet. Standard XHTTP responses are
	// bodyless, so closing here still preserves their reusable connections.
	_ = resp.Body.Close()
	return nil
}

func (c *DefaultDialerClient) Close() error {
	c.closed.Store(true)
	if !c.closeStarted.CompareAndSwap(false, true) {
		return nil
	}
	transport := c.client.Transport
	if h3Transport, ok := transport.(*http3.Transport); ok {
		return h3Transport.Close()
	}
	c.h2Connections.close()
	if idleCloser, ok := transport.(interface{ CloseIdleConnections() }); ok {
		idleCloser.CloseIdleConnections()
	}
	return nil
}

type WaitReadCloser struct {
	// Wait and the embedded ReadCloser are retained for source compatibility.
	// Built-in callers should construct this type with newWaitReadCloser and use
	// Set so publication remains synchronized.
	Wait chan struct{}
	io.ReadCloser

	readyOnce sync.Once
	mu        sync.Mutex
	closed    bool
}

func newWaitReadCloser() *WaitReadCloser {
	return &WaitReadCloser{Wait: make(chan struct{})}
}

func (w *WaitReadCloser) waitChannelLocked() chan struct{} {
	if w.Wait == nil {
		w.Wait = make(chan struct{})
	}
	return w.Wait
}

func (w *WaitReadCloser) signalReady(wait chan struct{}) {
	w.readyOnce.Do(func() {
		defer func() { _ = recover() }()
		close(wait)
	})
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.mu.Lock()
	wait := w.waitChannelLocked()
	if w.closed {
		w.mu.Unlock()
		rc.Close()
		w.signalReady(wait)
		return
	}
	w.ReadCloser = rc
	w.mu.Unlock()
	w.signalReady(wait)
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	w.mu.Lock()
	rc := w.ReadCloser
	wait := w.waitChannelLocked()
	w.mu.Unlock()
	if rc == nil {
		<-wait
		w.mu.Lock()
		rc = w.ReadCloser
		w.mu.Unlock()
	}
	if rc == nil {
		return 0, io.ErrClosedPipe
	}
	return rc.Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	rc := w.ReadCloser
	wait := w.waitChannelLocked()
	w.mu.Unlock()
	w.signalReady(wait)
	if rc != nil {
		return rc.Close()
	}
	return nil
}
