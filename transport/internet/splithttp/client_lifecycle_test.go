package splithttp

import (
	"context"
	"crypto/tls"
	stderrors "errors"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestPlainTLSHandshakeObservesRequestCancellation(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan stdnet.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	port := net.Port(listener.Addr().(*stdnet.TCPAddr).Port)
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &xtls.Config{
			ServerName:   "localhost",
			NextProtocol: []string{"h2"},
		},
	}
	client := createHTTPClient(net.TCPDestination(net.LocalHostIP, port), settings).(*DefaultDialerClient)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, _, _, err := client.OpenStream(ctx, "https://localhost/", "", nil, false)
		result <- err
	}()

	var peer stdnet.Conn
	select {
	case peer = <-accepted:
		defer peer.Close()
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("TLS test peer was not accepted")
	}
	cancel()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled TLS handshake unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request cancellation did not interrupt the plain TLS handshake")
	}

	// The failed-handshake branch owns the socket and must close it, not merely
	// return while leaving the peer half-open.
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	for {
		_, err := peer.Read(buffer)
		if err == nil {
			continue
		}
		if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
			t.Fatal("canceled TLS handshake left its network connection open")
		}
		break
	}
}

type closeTrackingRoundTripper struct {
	closeCount atomic.Int32
}

type closeSignalConn struct {
	stdnet.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeSignalConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type closeUnblocksResponseBody struct {
	closed chan struct{}
	once   sync.Once
}

type failingResponseBody struct {
	err error
}

func (b *failingResponseBody) Read([]byte) (int, error) { return 0, b.err }
func (*failingResponseBody) Close() error               { return nil }

func (b *closeUnblocksResponseBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, io.ErrClosedPipe
}

func (b *closeUnblocksResponseBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestPostPacketRejectsNonOKWithoutDrainingBody(t *testing.T) {
	body := &closeUnblocksResponseBody{closed: make(chan struct{})}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			request.Body.Close()
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Status:     "502 Bad Gateway",
				Body:       body,
			}, nil
		})},
		httpVersion: "2",
	}
	result := make(chan error, 1)
	go func() {
		result <- client.PostPacket(context.Background(), "https://example.test/upload", "session", "0", packetPayload("payload"))
	}()

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") {
			t.Fatalf("PostPacket error = %v, want 502 status", err)
		}
	case <-time.After(250 * time.Millisecond):
		body.Close()
		<-result
		t.Fatal("PostPacket tried to drain an unbounded non-OK response")
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("PostPacket did not close the non-OK response body")
	}
}

func TestPostPacketTreats200HeadersAsAcknowledgement(t *testing.T) {
	body := &closeUnblocksResponseBody{closed: make(chan struct{})}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			request.Body.Close()
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       body,
			}, nil
		})},
		httpVersion: "2",
	}
	result := make(chan error, 1)
	go func() {
		result <- client.PostPacket(context.Background(), "https://example.test/upload", "session", "0", packetPayload("payload"))
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("PostPacket rejected an acknowledged packet: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		body.Close()
		<-result
		t.Fatal("PostPacket waited for an unbounded acknowledged response body")
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("PostPacket did not close the acknowledged response body")
	}
	if client.IsClosed() {
		t.Fatal("closing an acknowledged response body poisoned the multiplexed transport")
	}
}

func TestPostPacketDoesNotFollowRedirect(t *testing.T) {
	for _, test := range []struct {
		name   string
		config *Config
	}{
		{name: "POST body", config: &Config{}},
		{name: "GET header", config: &Config{UplinkHTTPMethod: http.MethodGet, UplinkDataPlacement: PlacementHeader}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			client := &DefaultDialerClient{
				transportConfig: test.config,
				client: newHTTPClient(roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					if request.Body != nil {
						request.Body.Close()
					}
					if calls.Add(1) == 1 {
						return &http.Response{
							StatusCode: http.StatusFound,
							Status:     "302 Found",
							Header:     http.Header{"Location": []string{"https://redirected.example/upload"}},
							Body:       io.NopCloser(strings.NewReader("redirect")),
						}, nil
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				})),
				httpVersion: "2",
			}
			err := client.PostPacket(context.Background(), "https://example.test/upload", "session", "0", packetPayload("payload"))
			if err == nil || !strings.Contains(err.Error(), "302 Found") {
				t.Fatalf("PostPacket error = %v, want 302 status", err)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("redirecting packet request made %d round trips, want 1", got)
			}
		})
	}
}

func TestPostPacketDoesNotAddAbsoluteDeadline(t *testing.T) {
	observed := make(chan bool, 1)
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client: newHTTPClient(roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			request.Body.Close()
			_, ok := request.Context().Deadline()
			observed <- ok
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})),
		httpVersion: "2",
	}
	if err := client.PostPacket(context.Background(), "https://example.test/upload", "session", "0", packetPayload("payload")); err != nil {
		t.Fatal(err)
	}
	if <-observed {
		t.Fatal("PostPacket added an absolute deadline to the session context")
	}
}

func (*closeTrackingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, stderrors.New("not implemented")
}

func (t *closeTrackingRoundTripper) CloseIdleConnections() {
	t.closeCount.Add(1)
}

func TestOpenStreamReturnsPreConnectionFailure(t *testing.T) {
	wantErr := stderrors.New("dial failed")
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, wantErr
		})},
		httpVersion: "1.1",
	}
	reader, remote, local, err := client.OpenStream(context.Background(), "http://example.test/", "session", nil, false)
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("OpenStream error = %v, want %v", err, wantErr)
	}
	if reader != nil || remote != nil || local != nil {
		t.Fatalf("failed OpenStream returned reader=%v remote=%v local=%v", reader, remote, local)
	}
}

func TestOpenStreamReportsStreamDownNonOKStatusAfterConnection(t *testing.T) {
	terminal := make(chan error, 1)
	clientConn, peerConn := stdnet.Pipe()
	defer clientConn.Close()
	defer peerConn.Close()
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			httptrace.ContextClientTrace(request.Context()).GotConn(httptrace.GotConnInfo{Conn: clientConn})
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     "403 Forbidden",
				Body:       io.NopCloser(strings.NewReader("denied")),
			}, nil
		})},
		httpVersion: "1.1",
	}
	reader, _, _, err := client.OpenStreamWithTerminal(context.Background(), "http://example.test/", "session", nil, false, func(err error) {
		terminal <- err
	})
	if err != nil {
		t.Fatalf("OpenStream returned a post-connection status synchronously: %v", err)
	}
	if reader == nil {
		t.Fatal("connected stream-down returned no logical reader")
	}
	defer reader.Close()
	select {
	case callbackErr := <-terminal:
		if callbackErr == nil || !strings.Contains(callbackErr.Error(), "403 Forbidden") {
			t.Fatalf("terminal callback error = %v", callbackErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("non-OK stream-down did not invoke terminal callback")
	}
}

func TestOpenStreamReturnsBeforeStreamDownResponseHeaders(t *testing.T) {
	responseGate := make(chan struct{})
	responseDone := make(chan struct{})
	gotConnObserved := make(chan struct{})
	clientConn, peerConn := stdnet.Pipe()
	defer clientConn.Close()
	defer peerConn.Close()
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			httptrace.ContextClientTrace(request.Context()).GotConn(httptrace.GotConnInfo{Conn: clientConn})
			close(gotConnObserved)
			<-responseGate
			close(responseDone)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
		httpVersion: "2",
	}

	result := make(chan io.ReadCloser, 1)
	errResult := make(chan error, 1)
	go func() {
		reader, _, _, err := client.OpenStream(context.Background(), "https://example.test/", "session", nil, false)
		result <- reader
		errResult <- err
	}()
	select {
	case <-gotConnObserved:
	case <-time.After(2 * time.Second):
		close(responseGate)
		t.Fatal("stream-down request never reached GotConn")
	}

	var reader io.ReadCloser
	select {
	case reader = <-result:
		if err := <-errResult; err != nil {
			t.Fatalf("OpenStream failed after GotConn: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(responseGate)
		<-responseDone
		t.Fatal("OpenStream waited for stream-down response headers")
	}
	if reader == nil {
		t.Fatal("OpenStream returned a nil reader after GotConn")
	}
	close(responseGate)
	<-responseDone
	reader.Close()
}

func TestStreamDownFollowsRedirect(t *testing.T) {
	var calls atomic.Int32
	redirectedSession := make(chan string, 1)
	clientConn, peerConn := stdnet.Pipe()
	defer clientConn.Close()
	defer peerConn.Close()
	client := &DefaultDialerClient{
		transportConfig: &Config{SessionIDPlacement: PlacementHeader},
		client: newHTTPClient(roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			trace := httptrace.ContextClientTrace(request.Context())
			trace.GotConn(httptrace.GotConnInfo{Conn: clientConn})
			if calls.Add(1) == 1 {
				return &http.Response{
					StatusCode: http.StatusFound,
					Status:     "302 Found",
					Header:     http.Header{"Location": []string{"https://example.test/canonical"}},
					Body:       io.NopCloser(strings.NewReader("redirect")),
				}, nil
			}
			redirectedSession <- request.Header.Get("X-Session")
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader("tunnel")),
			}, nil
		})),
		httpVersion: "2",
	}

	reader, _, _, err := client.OpenStream(context.Background(), "https://example.test/original", "session", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "tunnel" {
		t.Fatalf("redirected stream payload = %q, want tunnel", payload)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("stream-down redirect made %d round trips, want 2", got)
	}
	if got := <-redirectedSession; got != "session" {
		t.Fatalf("redirected stream session header = %q, want session", got)
	}
}

func TestUploadStreamsDoNotFollowRedirect(t *testing.T) {
	for _, test := range []struct {
		name       string
		uploadOnly bool
	}{
		{name: "stream-up", uploadOnly: true},
		{name: "stream-one", uploadOnly: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			terminal := make(chan error, 1)
			clientConn, peerConn := stdnet.Pipe()
			defer clientConn.Close()
			defer peerConn.Close()
			client := &DefaultDialerClient{
				transportConfig: &Config{},
				client: newHTTPClient(roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					httptrace.ContextClientTrace(request.Context()).GotConn(httptrace.GotConnInfo{Conn: clientConn})
					if request.Body != nil {
						request.Body.Close()
					}
					if calls.Add(1) == 1 {
						return &http.Response{
							StatusCode: http.StatusFound,
							Status:     "302 Found",
							Header:     http.Header{"Location": []string{"https://redirected.example/upload"}},
							Body:       io.NopCloser(strings.NewReader("redirect")),
						}, nil
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				})),
				httpVersion: "2",
			}

			reader, _, _, err := client.OpenStreamWithTerminal(
				context.Background(),
				"https://example.test/upload",
				"session",
				strings.NewReader("payload"),
				test.uploadOnly,
				func(err error) { terminal <- err },
			)
			if err != nil {
				t.Fatalf("OpenStream returned a post-connection redirect synchronously: %v", err)
			}
			defer reader.Close()
			select {
			case terminalErr := <-terminal:
				if terminalErr == nil || !strings.Contains(terminalErr.Error(), "302 Found") {
					t.Fatalf("terminal callback error = %v, want 302 status", terminalErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("redirecting upload stream did not terminate")
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("redirecting upload stream made %d round trips, want 1", got)
			}
		})
	}
}

func TestOpenStreamReportsFailureAfterGotConn(t *testing.T) {
	wantErr := stderrors.New("request failed after connection")
	for _, test := range []struct {
		name       string
		version    string
		uploadOnly bool
		wantClosed bool
	}{
		{name: "H1 pool survives one socket failure", version: "1.1", uploadOnly: false, wantClosed: false},
		{name: "upload-only keeps legacy non-poisoning", version: "2", uploadOnly: true, wantClosed: false},
		{name: "multiplexed bidirectional stream keeps legacy retirement", version: "2", uploadOnly: false, wantClosed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			terminal := make(chan error, 1)
			client := &DefaultDialerClient{
				transportConfig: &Config{},
				client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					clientConn, peerConn := stdnet.Pipe()
					defer clientConn.Close()
					defer peerConn.Close()
					trace := httptrace.ContextClientTrace(request.Context())
					trace.GotConn(httptrace.GotConnInfo{Conn: clientConn})
					return nil, wantErr
				})},
				httpVersion: test.version,
			}
			reader, _, _, err := client.OpenStreamWithTerminal(context.Background(), "http://example.test/", "session", strings.NewReader("stream"), test.uploadOnly, func(err error) {
				terminal <- err
			})
			if err != nil {
				t.Fatalf("OpenStream returned the post-GotConn error synchronously: %v", err)
			}
			if reader == nil {
				t.Fatal("streaming OpenStream returned nil reader after GotConn")
			}
			defer reader.Close()
			select {
			case callbackErr := <-terminal:
				if !stderrors.Is(callbackErr, wantErr) {
					t.Fatalf("terminal callback error = %v, want %v", callbackErr, wantErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("post-GotConn failure did not invoke terminal callback")
			}
			if got := client.IsClosed(); got != test.wantClosed {
				t.Fatalf("client closed = %v, want %v", got, test.wantClosed)
			}
		})
	}
}

func TestUploadOnlyStreamReportsResponseBodyFailure(t *testing.T) {
	wantErr := stderrors.New("upload acknowledgement body failed")
	terminal := make(chan error, 1)
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			clientConn, peerConn := stdnet.Pipe()
			defer clientConn.Close()
			defer peerConn.Close()
			httptrace.ContextClientTrace(request.Context()).GotConn(httptrace.GotConnInfo{Conn: clientConn})
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       &failingResponseBody{err: wantErr},
			}, nil
		})},
		httpVersion: "2",
	}
	reader, _, _, err := client.OpenStreamWithTerminal(context.Background(), "https://example.test/upload", "session", strings.NewReader("stream"), true, func(err error) {
		terminal <- err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	select {
	case err := <-terminal:
		if !stderrors.Is(err, wantErr) {
			t.Fatalf("terminal error = %v, want %v", err, wantErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upload-only response-body failure was silently discarded")
	}
}

type trackingReadCloser struct {
	closed atomic.Int32
}

func (*trackingReadCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (r *trackingReadCloser) Close() error {
	r.closed.Add(1)
	return nil
}

func TestWaitReadCloserCloseBeforeSet(t *testing.T) {
	waitReader := newWaitReadCloser()
	if err := waitReader.Close(); err != nil {
		t.Fatal(err)
	}
	underlying := &trackingReadCloser{}
	waitReader.Set(underlying)
	if underlying.closed.Load() != 1 {
		t.Fatalf("late underlying reader closed %d times, want 1", underlying.closed.Load())
	}
	if _, err := waitReader.Read(make([]byte, 1)); !stderrors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read after early Close = %v, want io.ErrClosedPipe", err)
	}
}

func TestDefaultDialerClientCloseStillClosesTransportAfterFailure(t *testing.T) {
	transport := &closeTrackingRoundTripper{}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: transport},
	}
	client.closed.Store(true) // a prior network failure marked it unhealthy
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if transport.closeCount.Load() != 1 {
		t.Fatalf("CloseIdleConnections called %d times, want 1", transport.closeCount.Load())
	}
}

func TestRawConnRegistryClosesRegisteredAndLateH2Connections(t *testing.T) {
	registry := &rawConnRegistry{}
	registered, registeredPeer := stdnet.Pipe()
	defer registeredPeer.Close()
	if !registry.add(registered) {
		t.Fatal("open registry rejected its first connection")
	}
	registry.close()

	late, latePeer := stdnet.Pipe()
	defer latePeer.Close()
	if registry.add(late) {
		t.Fatal("closed registry accepted a late connection")
	}

	for name, peer := range map[string]stdnet.Conn{
		"registered": registeredPeer,
		"late":       latePeer,
	} {
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			// net.Pipe may report the peer close directly from SetReadDeadline.
			if !stderrors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			continue
		}
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatalf("%s connection remained open", name)
		}
	}
}

func TestRawConnRegistryAddCloseRaceAlwaysClosesConnection(t *testing.T) {
	for range 50 {
		registry := &rawConnRegistry{}
		conn, peer := stdnet.Pipe()
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			registry.add(conn)
		}()
		go func() {
			defer group.Done()
			<-start
			registry.close()
		}()
		close(start)
		group.Wait()
		registry.close()
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				peer.Close()
				t.Fatal("register-vs-close race left a connection open")
			}
		} else if !stderrors.Is(err, io.ErrClosedPipe) {
			peer.Close()
			t.Fatal(err)
		}
		peer.Close()
	}
}

func TestH2ClientCloseClosesTrackedActiveConnection(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		var server http2.Server
		server.ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			<-request.Context().Done()
		})})
	}()

	closed := make(chan struct{})
	registry := &rawConnRegistry{}
	transport := &http2.Transport{
		AllowHTTP:       true,
		IdleConnTimeout: 30 * time.Second,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (stdnet.Conn, error) {
			var dialer stdnet.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
			if err != nil {
				return nil, err
			}
			conn = &closeSignalConn{Conn: conn, closed: closed}
			if !registry.add(conn) {
				return nil, io.ErrClosedPipe
			}
			return conn, nil
		},
	}
	client := &DefaultDialerClient{client: newHTTPClient(transport), h2Connections: registry, httpVersion: "2"}
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	// releaseResources cancels the logical stream before the retired wrapper is
	// closed. The raw registry must close the physical H2 connection even though
	// the response body has not yet completed its own cleanup.
	cancel()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("retired H2 client left its active connection until idle timeout")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the tracked H2 connection did not stop the server stream")
	}
}

func TestExplicitlyClosedH1ClientRejectsAndReleasesPacket(t *testing.T) {
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: &closeTrackingRoundTripper{}},
		httpVersion:     "1.1",
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	payload := buf.New()
	if _, err := payload.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := client.PostPacket(context.Background(), "http://example.test/upload", "session", "0", buf.MultiBuffer{payload}); err == nil {
		t.Fatal("closed H1 client unexpectedly accepted a packet")
	}
	if payload.Len() != 0 {
		t.Fatalf("closed H1 client retained %d payload bytes", payload.Len())
	}
}

type failingDialerClient struct {
	err error
}

func (*failingDialerClient) IsClosed() bool { return false }
func (c *failingDialerClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return nil, nil, nil, c.err
}

func (*failingDialerClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}
func (*failingDialerClient) Close() error { return nil }

func TestDialRejectsDownloadSettingsWithoutDestination(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("invalid-download.example"), 443)
	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			DownloadSettings: &internet.StreamConfig{},
		},
		DownloadSettings: &internet.MemoryStreamConfig{
			ProtocolName:     protocolName,
			ProtocolSettings: &Config{},
		},
	}

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = nil
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	if _, err := Dial(context.Background(), dest, settings); err == nil {
		t.Fatal("downloadSettings without a destination unexpectedly succeeded")
	}
	zeroPortDest := net.TCPDestination(net.DomainAddress("download.example"), 0)
	settings.DownloadSettings.Destination = &zeroPortDest
	if _, err := Dial(context.Background(), dest, settings); err == nil {
		t.Fatal("downloadSettings with port zero unexpectedly succeeded")
	}
}

func TestDialFailureReleasesBothXmuxSessionLeases(t *testing.T) {
	mainDest := net.TCPDestination(net.DomainAddress("main.example"), 443)
	downDest := net.TCPDestination(net.DomainAddress("down.example"), 443)
	mainMemory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{DownloadSettings: &internet.StreamConfig{}},
	}
	downMemory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		Destination:      &downDest,
	}
	mainMemory.DownloadSettings = downMemory

	mainClient := &failingDialerClient{err: stderrors.New("main should not be opened first")}
	downErr := stderrors.New("download failed")
	downClient := &failingDialerClient{err: downErr}
	mainManager := NewXmuxManagerForHTTPVersion(nil, "2", func() XmuxConn {
		return mainClient
	})
	downManager := NewXmuxManagerForHTTPVersion(nil, "2", func() XmuxConn {
		return downClient
	})

	// Managers create their own XmuxClient wrappers, so capture those through
	// the acquired leases rather than the factory's DialerClient value.
	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{
		{Destination: mainDest, MemoryStreamConfig: mainMemory}: mainManager,
		{Destination: downDest, MemoryStreamConfig: downMemory}: downManager,
	}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	_, err := Dial(context.Background(), mainDest, mainMemory)
	if err == nil || (!stderrors.Is(err, downErr) && !strings.Contains(err.Error(), downErr.Error())) {
		t.Fatalf("Dial error = %v, want %v", err, downErr)
	}
	// Locate the manager-owned wrappers and verify the rollback reservations.
	var mainXmux, downXmux *XmuxClient
	mainManager.mu.Lock()
	if len(mainManager.xmuxClients) != 1 {
		mainManager.mu.Unlock()
		t.Fatalf("main manager has %d active clients, want 1", len(mainManager.xmuxClients))
	}
	mainXmux = mainManager.xmuxClients[0]
	mainManager.mu.Unlock()
	downManager.mu.Lock()
	if len(downManager.xmuxClients) != 1 {
		downManager.mu.Unlock()
		t.Fatalf("download manager has %d active clients, want 1", len(downManager.xmuxClients))
	}
	downXmux = downManager.xmuxClients[0]
	downManager.mu.Unlock()
	if got := mainXmux.Running.Load(); got != 0 {
		t.Fatalf("main Running after rollback = %d, want 0", got)
	}
	if got := downXmux.Running.Load(); got != 0 {
		t.Fatalf("download Running after rollback = %d, want 0", got)
	}
}

type terminalCallbackClient struct {
	callback chan func(error)
}

func (*terminalCallbackClient) IsClosed() bool { return false }
func (*terminalCallbackClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return io.NopCloser(strings.NewReader("")), &net.IPAddr{}, &net.IPAddr{}, nil
}

func (c *terminalCallbackClient) OpenStreamWithTerminal(_ context.Context, _ string, _ string, _ io.Reader, _ bool, onTerminalError func(error)) (io.ReadCloser, net.Addr, net.Addr, error) {
	c.callback <- onTerminalError
	return io.NopCloser(strings.NewReader("")), &net.IPAddr{}, &net.IPAddr{}, nil
}

func (*terminalCallbackClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}
func (*terminalCallbackClient) Close() error { return nil }

type blockingSetupClient struct {
	entered chan struct{}
}

func (*blockingSetupClient) IsClosed() bool { return false }
func (c *blockingSetupClient) OpenStream(ctx context.Context, _ string, _ string, _ io.Reader, _ bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	close(c.entered)
	<-ctx.Done()
	return nil, nil, nil, ctx.Err()
}

func (*blockingSetupClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}
func (*blockingSetupClient) Close() error { return nil }

func TestDialSetupReturnsRecordedTerminalError(t *testing.T) {
	mainDest := net.TCPDestination(net.DomainAddress("main-terminal.example"), 443)
	downDest := net.TCPDestination(net.DomainAddress("down-terminal.example"), 443)
	mainMemory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Mode: "stream-up", DownloadSettings: &internet.StreamConfig{}},
	}
	downMemory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		Destination:      &downDest,
	}
	mainMemory.DownloadSettings = downMemory

	mainClient := &blockingSetupClient{entered: make(chan struct{})}
	downClient := &terminalCallbackClient{callback: make(chan func(error), 1)}
	mainManager := NewXmuxManagerForHTTPVersion(nil, "2", func() XmuxConn { return mainClient })
	downManager := NewXmuxManagerForHTTPVersion(nil, "2", func() XmuxConn { return downClient })

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{
		{Destination: mainDest, MemoryStreamConfig: mainMemory}: mainManager,
		{Destination: downDest, MemoryStreamConfig: downMemory}: downManager,
	}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	result := make(chan error, 1)
	go func() {
		_, err := Dial(context.Background(), mainDest, mainMemory)
		result <- err
	}()
	var onTerminalError func(error)
	select {
	case onTerminalError = <-downClient.callback:
	case <-time.After(2 * time.Second):
		t.Fatal("download stream did not open")
	}
	select {
	case <-mainClient.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("upload stream did not enter setup")
	}
	wantErr := stderrors.New("download terminated during setup")
	onTerminalError(wantErr)
	select {
	case err := <-result:
		if !stderrors.Is(err, wantErr) && !strings.Contains(err.Error(), wantErr.Error()) {
			t.Fatalf("Dial error = %v, want %v", err, wantErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal download error did not stop upload setup")
	}
}

type packetFailDialerClient struct {
	err        error
	postCalled chan struct{}
	closed     atomic.Bool
	closeCount atomic.Int32
}

func (c *packetFailDialerClient) IsClosed() bool { return c.closed.Load() }
func (*packetFailDialerClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return io.NopCloser(strings.NewReader("")), &net.IPAddr{}, &net.IPAddr{}, nil
}

func (c *packetFailDialerClient) PostPacket(_ context.Context, _ string, _ string, _ string, payload buf.MultiBuffer) error {
	buf.ReleaseMulti(payload)
	c.closed.Store(true)
	select {
	case c.postCalled <- struct{}{}:
	default:
	}
	return c.err
}

func (c *packetFailDialerClient) Close() error {
	c.closeCount.Add(1)
	c.closed.Store(true)
	return nil
}

type successfulPacketDialerClient struct {
	posts      chan *successfulPacketDialerClient
	closed     atomic.Bool
	closeCount atomic.Int32
}

func (c *successfulPacketDialerClient) IsClosed() bool { return c.closed.Load() }
func (*successfulPacketDialerClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return io.NopCloser(strings.NewReader("")), &net.IPAddr{}, &net.IPAddr{}, nil
}

func (c *successfulPacketDialerClient) PostPacket(_ context.Context, _ string, _ string, _ string, payload buf.MultiBuffer) error {
	buf.ReleaseMulti(payload)
	c.posts <- c
	return nil
}

func (c *successfulPacketDialerClient) Close() error {
	c.closeCount.Add(1)
	c.closed.Store(true)
	return nil
}

func TestDialKeepsAndReleasesRotatedPacketAffinity(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("packet-affinity.example"), 80)
	memory := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			Mode:               "packet-up",
			ScMaxEachPostBytes: &RangeConfig{From: 1, To: 1},
		},
	}
	posts := make(chan *successfulPacketDialerClient, 4)
	var clientsMu sync.Mutex
	var clients []*successfulPacketDialerClient
	manager := NewXmuxManagerForHTTPVersion(&XmuxConfig{
		MaxConcurrency:   &RangeConfig{From: -1, To: -1},
		MaxConnections:   &RangeConfig{From: 2, To: 2},
		CMaxReuseTimes:   &RangeConfig{From: 1, To: 1},
		HMaxRequestTimes: &RangeConfig{From: 2, To: 2},
	}, "1.1", func() XmuxConn {
		client := &successfulPacketDialerClient{posts: posts}
		clientsMu.Lock()
		clients = append(clients, client)
		clientsMu.Unlock()
		return client
	})

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{{Destination: dest, MemoryStreamConfig: memory}: manager}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	conn, err := Dial(context.Background(), dest, memory)
	if err != nil {
		t.Fatal(err)
	}
	var used [3]*successfulPacketDialerClient
	for i := range used {
		if _, err := conn.Write([]byte{'a' + byte(i)}); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		select {
		case used[i] = <-posts:
		case <-time.After(2 * time.Second):
			conn.Close()
			t.Fatalf("packet %d was not posted", i)
		}
	}
	if used[0] == used[1] || used[1] != used[2] {
		conn.Close()
		t.Fatalf("packet clients = [%p %p %p], want original then one reused replacement", used[0], used[1], used[2])
	}
	clientsMu.Lock()
	created := append([]*successfulPacketDialerClient(nil), clients...)
	clientsMu.Unlock()
	if len(created) != 2 {
		conn.Close()
		t.Fatalf("three packets created %d clients, want 2", len(created))
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		allClosedOnce := true
		for _, client := range created {
			if client.closeCount.Load() != 1 {
				allClosedOnce = false
				break
			}
		}
		if allClosedOnce {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("closing the logical connection left close counts %d and %d", created[0].closeCount.Load(), created[1].closeCount.Load())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFatalPacketUploadReleasesLogicalSession(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("packet.example"), 80)
	memory := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			Mode:               "packet-up",
			ScMaxEachPostBytes: &RangeConfig{From: 1024, To: 1024},
		},
	}
	wantErr := stderrors.New("packet upload failed")
	fake := &packetFailDialerClient{err: wantErr, postCalled: make(chan struct{}, 1)}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })
	manager.enableH1PacketDownAdmission()

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{
		{Destination: dest, MemoryStreamConfig: memory}: manager,
	}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	conn, err := Dial(context.Background(), dest, memory)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := len(manager.h1PacketDownSlots); got != 1 {
		t.Fatalf("H1 packet-down admissions after Dial = %d, want 1", got)
	}
	if _, err := conn.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fake.postCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("packet upload did not run")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		active := len(manager.xmuxClients)
		manager.mu.Unlock()
		if active == 0 && fake.closeCount.Load() == 1 && len(manager.h1PacketDownSlots) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	manager.mu.Lock()
	active := len(manager.xmuxClients)
	manager.mu.Unlock()
	t.Fatalf("fatal upload left active clients=%d closeCount=%d H1 packet-down admissions=%d", active, fake.closeCount.Load(), len(manager.h1PacketDownSlots))
}

func TestFatalPacketUploadDoesNotLaunchRemainingChunks(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("packet-stop.example"), 80)
	transportConfig := &Config{
		Mode:               "packet-up",
		ScMaxEachPostBytes: &RangeConfig{From: 1, To: 1},
	}
	memory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: transportConfig,
	}
	wantErr := stderrors.New("first packet failed")
	firstPost := make(chan struct{})
	var postCount atomic.Int32
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
		if request.Body != nil {
			_, _ = io.Copy(io.Discard, request.Body)
			request.Body.Close()
		}
		if postCount.Add(1) == 1 {
			close(firstPost)
		}
		return nil, wantErr
	})
	manager := NewXmuxManagerForHTTPVersion(&XmuxConfig{
		MaxConcurrency:   &RangeConfig{From: -1, To: -1},
		MaxConnections:   &RangeConfig{From: 1, To: 1},
		HMaxRequestTimes: &RangeConfig{From: 100, To: 100},
	}, "2", func() XmuxConn {
		return &DefaultDialerClient{
			transportConfig: transportConfig,
			client:          newHTTPClient(transport),
			httpVersion:     "2",
		}
	})

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{{Destination: dest, MemoryStreamConfig: memory}: manager}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	conn, err := Dial(context.Background(), dest, memory)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstPost:
	case <-time.After(2 * time.Second):
		t.Fatal("first packet was not posted")
	}
	time.Sleep(50 * time.Millisecond)
	if got := postCount.Load(); got != 1 {
		t.Fatalf("fatal first packet launched %d chunks, want exactly 1", got)
	}
}

type terminalPacketDialerClient struct {
	callback chan func(error)
}

func (*terminalPacketDialerClient) IsClosed() bool { return false }
func (c *terminalPacketDialerClient) OpenStream(ctx context.Context, url, sessionID string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return c.OpenStreamWithTerminal(ctx, url, sessionID, body, uploadOnly, nil)
}

func (c *terminalPacketDialerClient) OpenStreamWithTerminal(_ context.Context, _ string, _ string, _ io.Reader, _ bool, callback func(error)) (io.ReadCloser, net.Addr, net.Addr, error) {
	c.callback <- callback
	return io.NopCloser(strings.NewReader("")), &net.IPAddr{}, &net.IPAddr{}, nil
}

func (*terminalPacketDialerClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}
func (*terminalPacketDialerClient) Close() error { return nil }

func TestTerminalDownloadInterruptsPacketWriter(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("terminal-write.example"), 80)
	memory := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			Mode:               "packet-up",
			ScMaxEachPostBytes: &RangeConfig{From: 1, To: 1},
		},
	}
	fake := &terminalPacketDialerClient{callback: make(chan func(error), 1)}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{{Destination: dest, MemoryStreamConfig: memory}: manager}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	conn, err := Dial(context.Background(), dest, memory)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	callback := <-fake.callback
	callback(stderrors.New("terminal download failure"))

	result := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("x"))
		result <- err
	}()
	select {
	case err := <-result:
		if !stderrors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Write error = %v, want io.ErrClosedPipe", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked after the terminal download failure")
	}
}

type terminalDuringOpenClient struct {
	err    error
	closed atomic.Bool
}

func (c *terminalDuringOpenClient) IsClosed() bool { return c.closed.Load() }
func (c *terminalDuringOpenClient) OpenStream(ctx context.Context, url, sessionID string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return c.OpenStreamWithTerminal(ctx, url, sessionID, body, uploadOnly, nil)
}

func (c *terminalDuringOpenClient) OpenStreamWithTerminal(_ context.Context, _ string, _ string, _ io.Reader, _ bool, onTerminalError func(error)) (io.ReadCloser, net.Addr, net.Addr, error) {
	c.closed.Store(true)
	if onTerminalError != nil {
		onTerminalError(c.err)
	}
	return io.NopCloser(strings.NewReader("")), &net.IPAddr{}, &net.IPAddr{}, nil
}

func (*terminalDuringOpenClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}

func (c *terminalDuringOpenClient) Close() error {
	c.closed.Store(true)
	return nil
}

func TestDialDoesNotCommitKnownTerminalFailure(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("terminal.example"), 80)
	memory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Mode: "stream-one"},
	}
	wantErr := stderrors.New("terminal during setup")
	fake := &terminalDuringOpenClient{err: wantErr}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{
		{Destination: dest, MemoryStreamConfig: memory}: manager,
	}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	conn, err := Dial(context.Background(), dest, memory)
	if conn != nil {
		conn.Close()
		t.Fatal("Dial returned a connection after a recorded terminal failure")
	}
	if err == nil || (!stderrors.Is(err, wantErr) && !strings.Contains(err.Error(), wantErr.Error())) {
		t.Fatalf("Dial error = %v, want %v", err, wantErr)
	}
}

type contextObservingDialerClient struct {
	contexts chan context.Context
	block    bool
}

func (*contextObservingDialerClient) IsClosed() bool { return false }
func (c *contextObservingDialerClient) OpenStream(ctx context.Context, _ string, _ string, _ io.Reader, _ bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	c.contexts <- ctx
	if c.block {
		<-ctx.Done()
		return nil, nil, nil, ctx.Err()
	}
	return io.NopCloser(strings.NewReader("")), &net.IPAddr{}, &net.IPAddr{}, nil
}

func (*contextObservingDialerClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}
func (*contextObservingDialerClient) Close() error { return nil }

func TestDialSetupHonorsCallerCancellation(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("cancel-setup.example"), 80)
	memory := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{Mode: "packet-up"}}
	fake := &contextObservingDialerClient{contexts: make(chan context.Context, 1), block: true}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{{Destination: dest, MemoryStreamConfig: memory}: manager}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	dialCtx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := Dial(dialCtx, dest, memory)
		result <- err
	}()
	select {
	case <-fake.contexts:
	case <-time.After(2 * time.Second):
		t.Fatal("Dial did not enter OpenStream")
	}
	cancel()
	select {
	case err := <-result:
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("Dial error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceling the caller context did not stop Dial setup")
	}
}

func TestDialSetupPreservesDeadlineExceeded(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("deadline-setup.example"), 80)
	memory := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{Mode: "packet-up"}}
	fake := &contextObservingDialerClient{contexts: make(chan context.Context, 1), block: true}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{{Destination: dest, MemoryStreamConfig: memory}: manager}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	dialCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := Dial(dialCtx, dest, memory)
		result <- err
	}()
	select {
	case <-fake.contexts:
	case <-time.After(2 * time.Second):
		t.Fatal("Dial did not enter OpenStream")
	}
	select {
	case err := <-result:
		if !stderrors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dial error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller deadline did not stop Dial setup")
	}
}

func TestCommittedConnectionDetachesCallerCancellation(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("detach-context.example"), 80)
	memory := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{Mode: "packet-up"}}
	fake := &contextObservingDialerClient{contexts: make(chan context.Context, 1)}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{{Destination: dest, MemoryStreamConfig: memory}: manager}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	dialCtx, cancel := context.WithCancel(context.Background())
	conn, err := Dial(dialCtx, dest, memory)
	if err != nil {
		t.Fatal(err)
	}
	sessionCtx := <-fake.contexts
	cancel()
	select {
	case <-sessionCtx.Done():
		conn.Close()
		t.Fatal("committed session was canceled with the short-lived Dial context")
	case <-time.After(100 * time.Millisecond):
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sessionCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("closing the logical connection did not cancel its session context")
	}
}
