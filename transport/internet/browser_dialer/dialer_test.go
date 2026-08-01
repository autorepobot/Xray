package browser_dialer

import (
	"context"
	"encoding/json"
	"errors"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/platform"
)

func useTestConnections(t *testing.T, connections chan *websocket.Conn) {
	t.Helper()
	mu.Lock()
	previous := conns
	conns = connections
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		conns = previous
		mu.Unlock()
	})
}

func TestDialGetContextCancelsWhileWaitingForBrowser(t *testing.T) {
	useTestConnections(t, make(chan *websocket.Conn))
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := DialGetContext(ctx, "https://example.test/stream", http.Header{}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialGetContext error = %v, want context deadline", err)
	}
}

func TestDialWSContextCancelsWhileWaitingForBrowser(t *testing.T) {
	useTestConnections(t, make(chan *websocket.Conn))
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := DialWSContext(ctx, "wss://example.test/stream", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialWSContext error = %v, want context deadline", err)
	}
}

func TestDialTaskContextRetriesAfterQueueGenerationChanges(t *testing.T) {
	accepted := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err == nil {
			accepted <- conn
		}
	}))
	defer server.Close()

	browserConn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer browserConn.Close()
	serverConn := <-accepted
	defer serverConn.Close()

	oldConnections := make(chan *websocket.Conn)
	newConnections := make(chan *websocket.Conn, 1)
	useTestConnections(t, oldConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan *websocket.Conn, 1)
	resultErr := make(chan error, 1)
	go func() {
		conn, err := dialTaskContext(ctx, task{Method: "GET", URL: "https://example.test/stream"})
		if err != nil {
			resultErr <- err
			return
		}
		result <- conn
	}()

	// Deliver the closed-queue sentinel while holding mu, then publish the next
	// generation before the consumer can validate the queue it received from.
	deadline := time.Now().Add(time.Second)
	delivered := false
	for !delivered && time.Now().Before(deadline) {
		mu.Lock()
		select {
		case oldConnections <- nil:
			conns = newConnections
			delivered = true
		default:
		}
		mu.Unlock()
		if !delivered {
			time.Sleep(time.Millisecond)
		}
	}
	if !delivered {
		t.Fatal("dial task never started waiting on the old connection queue")
	}

	newConnections <- serverConn
	_, taskData, err := browserConn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var deliveredTask task
	if err := json.Unmarshal(taskData, &deliveredTask); err != nil {
		t.Fatal(err)
	}
	if deliveredTask.Method != "GET" {
		t.Fatalf("delivered task method = %q, want GET", deliveredTask.Method)
	}
	if err := browserConn.WriteMessage(websocket.TextMessage, []byte("ok")); err != nil {
		t.Fatal(err)
	}

	select {
	case conn := <-result:
		if conn != serverConn {
			t.Fatal("dial task returned a connection from the stale queue generation")
		}
	case err := <-resultErr:
		t.Fatalf("dialTaskContext returned after reload instead of retrying: %v", err)
	case <-ctx.Done():
		t.Fatal("dialTaskContext did not retry the new queue generation")
	}
}

func TestHTTPExtraPreservesCookiesWithoutHeaders(t *testing.T) {
	extra := httpExtraFromHeadersAndCookies(http.Header{}, []*http.Cookie{{Name: "session", Value: "secret"}})
	if extra == nil {
		t.Fatal("cookies-only browser request lost its HTTP extra")
	}
	if got := extra.Cookies["session"]; got != "secret" {
		t.Fatalf("session cookie = %q, want secret", got)
	}
}

func TestReloadBindFailureDoesNotAdvertiseBrowserDialer(t *testing.T) {
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	name := platform.BrowserDialerAddress
	previous, hadPrevious := os.LookupEnv(name)
	if err := os.Setenv(name, listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv(name, previous)
		} else {
			_ = os.Unsetenv(name)
		}
		Reload()
	})

	Reload()
	if HasBrowserDialer() {
		t.Fatal("failed browser listener was advertised as available")
	}
}

func TestReloadClosesListenerBeforeServeRegistration(t *testing.T) {
	name := platform.BrowserDialerAddress
	previous, hadPrevious := os.LookupEnv(name)
	if err := os.Setenv(name, ""); err != nil {
		t.Fatal(err)
	}
	Reload()
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv(name, previous)
		} else {
			_ = os.Unsetenv(name)
		}
		Reload()
	})

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()

	// Reproduce the interval after net.Listen succeeds but before Serve records
	// the listener inside http.Server. Server.Close alone is a no-op here.
	mu.Lock()
	currentAddr = addr
	server = &http.Server{}
	browserListener = listener
	conns = make(chan *websocket.Conn, 1)
	mu.Unlock()

	Reload()
	rebound, err := stdnet.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Reload retained a pre-Serve listener: %v", err)
	}
	rebound.Close()

	if err := os.Setenv(name, addr); err != nil {
		t.Fatal(err)
	}
	Reload()
	if !HasBrowserDialer() {
		t.Fatal("browser dialer could not re-enable on the same address")
	}
}

func TestDialPacketContextCancelsFinalBrowserAcknowledgement(t *testing.T) {
	accepted := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err == nil {
			accepted <- conn
		}
	}))
	defer server.Close()

	browserConn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer browserConn.Close()
	serverConn := <-accepted
	connections := make(chan *websocket.Conn, 1)
	connections <- serverConn
	useTestConnections(t, connections)

	payloadSeen := make(chan struct{})
	browserDone := make(chan error, 1)
	go func() {
		if _, _, err := browserConn.ReadMessage(); err != nil {
			browserDone <- err
			return
		}
		if err := browserConn.WriteMessage(websocket.TextMessage, []byte("ok")); err != nil {
			browserDone <- err
			return
		}
		if _, _, err := browserConn.ReadMessage(); err != nil {
			browserDone <- err
			return
		}
		close(payloadSeen)
		_, _, err := browserConn.ReadMessage()
		browserDone <- err
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- DialPacketContext(ctx, "POST", "https://example.test/upload", http.Header{}, nil, []byte("payload"))
	}()
	select {
	case <-payloadSeen:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("browser did not receive the packet payload")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialPacketContext error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not interrupt the final browser acknowledgement")
	}
	select {
	case <-browserDone:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not close the browser websocket")
	}
}

func TestEmbeddedHTTPTaskLifecycleAndCookieCoordination(t *testing.T) {
	page := string(webpage)
	if strings.Count(page, "new AbortController()") < 2 {
		t.Fatal("embedded browser dialer does not make both fetch paths abortable")
	}
	if strings.Count(page, "await fetchWithTaskCookies(task, requestInit, controller.signal);") != 2 {
		t.Fatal("embedded browser dialer does not route both fetch paths through cookie isolation")
	}
	if strings.Contains(page, "cookieFetchTail") ||
		!strings.Contains(page, `withCookieGate("read"`) ||
		!strings.Contains(page, `withCookieGate("write"`) ||
		!strings.Contains(page, "cookieGateReaders") {
		t.Fatal("embedded browser dialer does not use a shared/exclusive cookie gate")
	}
	if !strings.Contains(page, "navigator.locks.request(") ||
		!strings.Contains(page, `"xray-browser-dialer-cookie-jar"`) ||
		!strings.Contains(page, "window.isSecureContext") {
		t.Fatal("embedded browser dialer does not coordinate its cookie gate across same-origin tabs when supported")
	}
	if !strings.Contains(page, `requestInit.credentials = "include"`) {
		t.Fatal("embedded browser dialer does not retain compatible explicit-cookie credentials")
	}
	if !strings.Contains(page, "openWebSocketWithCookieIsolation(task, ws)") {
		t.Fatal("embedded browser dialer WebSocket handshakes bypass cookie isolation")
	}
	if strings.Count(page, "bridge.readyState !== WebSocket.OPEN") < 2 {
		t.Fatal("embedded browser dialer can orphan an upstream socket after its bridge closes")
	}
	if !strings.Contains(page, "let wss = null;") ||
		!strings.Contains(page, "if (wss && wss.readyState < WebSocket.CLOSING) wss.close();") {
		t.Fatal("embedded browser dialer does not close an upstream socket after a post-handshake failure")
	}
	if !strings.Contains(page, "if (!assigned)") || !strings.Contains(page, "assigned = true;") {
		t.Fatal("embedded browser dialer does not replenish idle sockets rejected before task assignment")
	}
	if !strings.Contains(page, "const maxControlReconnectFailures = 5;") ||
		!strings.Contains(page, "const maxControlReconnectDelayMs = 8000;") ||
		!strings.Contains(page, "controlReconnectFailures >= maxControlReconnectFailures") ||
		!strings.Contains(page, "Date.now() < controlReconnectAfter") ||
		!strings.Contains(page, "controlReconnectSuspended = true") ||
		!strings.Contains(page, "stableControlConnectionMs") {
		t.Fatal("embedded browser dialer does not bound failed control-socket reconnection")
	}
	if !strings.Contains(page, `ws.send("ok")`) {
		t.Fatal("embedded browser dialer does not preserve the original stream setup acknowledgement")
	}
}
