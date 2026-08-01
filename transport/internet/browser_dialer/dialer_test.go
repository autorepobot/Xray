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
	mu.Lock()
	previousStrict := currentStrict
	currentStrict = true
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		currentStrict = previousStrict
		mu.Unlock()
	})

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
	if !deliveredTask.Strict {
		t.Fatal("dial task did not carry the current strict policy to an existing browser page")
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

func TestBrowserDialerWebSocketRequiresSameOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "browser same origin", origin: "http://127.0.0.1:8080", want: true},
		{name: "browser cross origin", origin: "https://attacker.example", want: false},
		{name: "non-browser without origin", want: true},
		{name: "opaque origin", origin: "null", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/websocket", nil)
			request.Host = "127.0.0.1:8080"
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if got := browserDialerSameOrigin(request); got != test.want {
				t.Fatalf("browserDialerSameOrigin() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestBrowserDialerOriginPolicyDefaultsToCompatibility(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/websocket", nil)
	request.Host = "127.0.0.1:8080"
	request.Header.Set("Origin", "https://attacker.example")
	if !newBrowserDialerUpgrader(false).CheckOrigin(request) {
		t.Fatal("compatibility policy rejected the historically accepted Origin")
	}
	if newBrowserDialerUpgrader(true).CheckOrigin(request) {
		t.Fatal("strict policy accepted a cross-origin browser handshake")
	}
}

func TestBrowserDialerHostPolicyRejectsDNSRebinding(t *testing.T) {
	tests := []struct {
		name        string
		listenAddr  string
		requestHost string
		want        bool
	}{
		{name: "loopback literal", listenAddr: "127.0.0.1:8080", requestHost: "127.0.0.1:8080", want: true},
		{name: "loopback localhost", listenAddr: "127.0.0.1:8080", requestHost: "localhost:8080", want: true},
		{name: "loopback rebound domain", listenAddr: "127.0.0.1:8080", requestHost: "evil.test:8080", want: false},
		{name: "wildcard literal", listenAddr: ":8080", requestHost: "192.0.2.10:8080", want: true},
		{name: "wildcard localhost", listenAddr: "0.0.0.0:8080", requestHost: "localhost:8080", want: true},
		{name: "wildcard rebound domain", listenAddr: "0.0.0.0:8080", requestHost: "evil.test:8080", want: false},
		{name: "explicit hostname", listenAddr: "dialer.example:8080", requestHost: "dialer.example:443", want: true},
		{name: "different hostname", listenAddr: "dialer.example:8080", requestHost: "evil.test:8080", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := browserDialerHostAllowed(test.requestHost, test.listenAddr); got != test.want {
				t.Fatalf("browserDialerHostAllowed(%q, %q) = %v, want %v", test.requestHost, test.listenAddr, got, test.want)
			}
		})
	}
}

func TestBrowserDialerPageDoesNotExposeTokenThroughCORS(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	request.Header.Set("Origin", "https://attacker.example")
	serveBrowserDialerPage(recorder, request, []byte("secret-token"), true)

	response := recorder.Result()
	defer response.Body.Close()
	if allowOrigin := response.Header.Get("Access-Control-Allow-Origin"); allowOrigin != "" {
		t.Fatalf("browser page exposes CORS origin %q", allowOrigin)
	}
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestBrowserDialerPageRejectsStateChangingMethods(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/", nil)
	serveBrowserDialerPage(recorder, request, []byte("secret-token"), true)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestBrowserDialerPageCompatibilityPolicy(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://proxy.example/browser", nil)
	request.Header.Set("Origin", "https://embedding.example")
	serveBrowserDialerPage(recorder, request, []byte("legacy-page"), false)

	response := recorder.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("compatibility page status = %d, want 200", response.StatusCode)
	}
	if allowOrigin := response.Header.Get("Access-Control-Allow-Origin"); allowOrigin != "*" {
		t.Fatalf("compatibility page Access-Control-Allow-Origin = %q, want *", allowOrigin)
	}
	if body := recorder.Body.String(); body != "legacy-page" {
		t.Fatalf("compatibility page body = %q", body)
	}
}

func TestReloadTracksBrowserDialerStrictPolicy(t *testing.T) {
	addressName := platform.BrowserDialerAddress
	strictName := platform.BrowserDialerStrict
	previousAddress, hadAddress := os.LookupEnv(addressName)
	previousStrict, hadStrict := os.LookupEnv(strictName)
	if err := os.Setenv(addressName, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv(strictName); err != nil {
		t.Fatal(err)
	}
	Reload()
	if currentStrict {
		t.Fatal("Browser Dialer strict policy is not disabled by default")
	}
	if err := os.Setenv(strictName, "true"); err != nil {
		t.Fatal(err)
	}
	Reload()
	if !currentStrict {
		t.Fatal("Reload did not apply Browser Dialer strict policy")
	}
	if err := os.Setenv(strictName, "false"); err != nil {
		t.Fatal(err)
	}
	Reload()
	if currentStrict {
		t.Fatal("Reload did not explicitly disable Browser Dialer strict policy")
	}
	t.Cleanup(func() {
		if hadAddress {
			_ = os.Setenv(addressName, previousAddress)
		} else {
			_ = os.Unsetenv(addressName)
		}
		if hadStrict {
			_ = os.Setenv(strictName, previousStrict)
		} else {
			_ = os.Unsetenv(strictName)
		}
		Reload()
	})
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

func TestEmbeddedHTTPTasksPreserveCompatibilityAndOfferStrictMode(t *testing.T) {
	page := string(webpage)
	if strings.Count(page, `requestInit.redirect = "error";`) != 2 {
		t.Fatal("strict Browser Dialer policy does not disable redirects for both fetch paths")
	}
	if !strings.Contains(page, "task.strict && response.status !== 200") ||
		!strings.Contains(page, "task.strict && response.status === 200") ||
		!strings.Contains(page, "!task.strict && response.ok") {
		t.Fatal("embedded browser dialer does not preserve compatible 2xx handling behind an opt-in strict policy")
	}
	if strings.Count(page, "new AbortController()") < 2 {
		t.Fatal("embedded browser dialer does not make both fetch paths abortable")
	}
	if strings.Count(page, "await fetchWithTaskCookies(task, requestInit, controller.signal);") != 2 {
		t.Fatal("embedded browser dialer does not route both fetch paths through cookie isolation")
	}
	if !strings.Contains(page, "if (!task.strict || !task.extra || !task.extra.cookies)") ||
		!strings.Contains(page, "target.protocol !== window.location.protocol") ||
		!strings.Contains(page, "target.hostname !== window.location.hostname") {
		t.Fatal("embedded browser dialer does not confine cookie scope checks to strict mode")
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
	if !strings.Contains(page, `requestInit.credentials = "include"`) ||
		!strings.Contains(page, `requestInit.credentials = "omit"`) {
		t.Fatal("embedded browser dialer does not preserve compatible credentials with an opt-in strict override")
	}
	if !strings.Contains(page, "openWebSocketWithCookieIsolation(task, ws)") {
		t.Fatal("embedded browser dialer WebSocket handshakes bypass cookie isolation")
	}
	if !strings.Contains(page, "if (task.strict)") || !strings.Contains(page, "handshakeTimer = setTimeout(() => fail(), 30000)") {
		t.Fatal("embedded browser dialer does not confine its new WebSocket handshake timeout to strict mode")
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
	if !strings.Contains(page, "if (!task.strict)") || !strings.Contains(page, `ws.send("ok")`) {
		t.Fatal("embedded browser dialer does not preserve the original stream setup acknowledgement")
	}
}
