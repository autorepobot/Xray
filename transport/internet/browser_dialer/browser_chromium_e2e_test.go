package browser_dialer

import (
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/platform"
)

// TestBrowserDialerChromiumCompatibilityAndParallelWebSockets is opt-in
// because it launches a real Chromium-family browser. Set
// XRAY_BROWSER_E2E_CHROME to the Chrome/Chromium/Edge executable to run it.
func TestBrowserDialerChromiumCompatibilityAndParallelWebSockets(t *testing.T) {
	chromePath := os.Getenv("XRAY_BROWSER_E2E_CHROME")
	if chromePath == "" {
		t.Skip("set XRAY_BROWSER_E2E_CHROME to run the real-browser test")
	}
	if _, err := os.Stat(chromePath); err != nil {
		t.Fatalf("Chromium executable: %v", err)
	}

	restoreBrowserDialerEnvironment(t)
	browserAddress := reserveBrowserDialerAddress(t)
	if err := os.Setenv(platform.BrowserDialerAddress, browserAddress); err != nil {
		t.Fatal(err)
	}
	// A canonical false value takes precedence over a possibly inherited
	// XRAY_BROWSER_DIALER_STRICT alias.
	if err := os.Setenv(platform.BrowserDialerStrict, "false"); err != nil {
		t.Fatal(err)
	}
	Reload()

	mu.Lock()
	listener := browserListener
	mu.Unlock()
	if listener == nil {
		t.Fatal("Browser Dialer did not create its listener")
	}
	browserTarget, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	reverseProxy := httputil.NewSingleHostReverseProxy(browserTarget)

	ambientSeen := make(chan bool, 1)
	redirectSeen := make(chan bool, 1)
	streamArrival := make(chan struct{}, 1)
	streamRelease := make(chan struct{})
	var streamReleaseOnce sync.Once
	releaseStream := func() { streamReleaseOnce.Do(func() { close(streamRelease) }) }
	t.Cleanup(releaseStream)
	strictNoAmbientSeen := make(chan bool, 1)
	strictExplicitSeen := make(chan bool, 1)
	explicitCookieArrivals := make(chan string, 2)
	postCookieSeen := make(chan bool, 1)
	firstCookieRelease := make(chan struct{})
	var explicitCookieCount atomic.Int32
	var cookieReleaseOnce sync.Once
	releaseFirstCookie := func() { cookieReleaseOnce.Do(func() { close(firstCookieRelease) }) }
	t.Cleanup(releaseFirstCookie)
	wsArrivals := make(chan struct{}, 2)
	wsUpgradeResults := make(chan error, 2)
	wsRelease := make(chan struct{})
	var releaseOnce sync.Once
	var controlUpgrades atomic.Int32
	releaseWebSockets := func() { releaseOnce.Do(func() { close(wsRelease) }) }
	t.Cleanup(releaseWebSockets)

	upstreamUpgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{"ZWQtMA", "ZWQtMQ"},
	}
	proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/bootstrap":
			http.SetCookie(writer, &http.Cookie{Name: "ambient", Value: "legacy", Path: "/"})
			http.Redirect(writer, request, "/", http.StatusFound)
		case "/compat-204":
			cookie, cookieErr := request.Cookie("ambient")
			ambientSeen <- cookieErr == nil && cookie.Value == "legacy"
			writer.WriteHeader(http.StatusNoContent)
		case "/compat-redirect":
			http.Redirect(writer, request, "/compat-target", http.StatusFound)
		case "/compat-target":
			cookie, cookieErr := request.Cookie("ambient")
			redirectSeen <- cookieErr == nil && cookie.Value == "legacy"
			writer.WriteHeader(http.StatusOK)
		case "/compat-stream-404":
			streamArrival <- struct{}{}
			select {
			case <-streamRelease:
			case <-request.Context().Done():
				return
			}
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte("legacy-error-body"))
		case "/strict-no-ambient":
			_, cookieErr := request.Cookie("ambient")
			strictNoAmbientSeen <- cookieErr == http.ErrNoCookie
			writer.WriteHeader(http.StatusOK)
		case "/strict-204":
			writer.WriteHeader(http.StatusNoContent)
		case "/strict-redirect":
			http.Redirect(writer, request, "/strict-target", http.StatusFound)
		case "/strict-target":
			writer.WriteHeader(http.StatusOK)
		case "/strict-stream-404":
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte("strict-error-body"))
		case "/strict-explicit":
			cookie, cookieErr := request.Cookie("strictTemporary")
			strictExplicitSeen <- cookieErr == nil && cookie.Value == "strict-value"
			writer.WriteHeader(http.StatusOK)
		case "/explicit-cookie":
			ambient, ambientErr := request.Cookie("ambient")
			temporary, temporaryErr := request.Cookie("temporary")
			if request.URL.Query().Get("check") == "1" {
				postCookieSeen <- ambientErr == nil && ambient.Value == "legacy" && temporaryErr == http.ErrNoCookie
				writer.WriteHeader(http.StatusOK)
				return
			}
			if temporaryErr != nil {
				explicitCookieArrivals <- ""
			} else {
				explicitCookieArrivals <- temporary.Value
			}
			if explicitCookieCount.Add(1) == 1 {
				select {
				case <-firstCookieRelease:
				case <-request.Context().Done():
					return
				}
			}
			writer.WriteHeader(http.StatusOK)
		case "/parallel-ws":
			wsArrivals <- struct{}{}
			select {
			case <-wsRelease:
			case <-request.Context().Done():
				return
			}
			conn, upgradeErr := upstreamUpgrader.Upgrade(writer, request, nil)
			wsUpgradeResults <- upgradeErr
			if upgradeErr != nil {
				return
			}
			defer conn.Close()
			for {
				if _, _, readErr := conn.ReadMessage(); readErr != nil {
					return
				}
			}
		case "/websocket":
			controlUpgrades.Add(1)
			reverseProxy.ServeHTTP(writer, request)
		default:
			reverseProxy.ServeHTTP(writer, request)
		}
	}))
	proxyListener, err := stdnet.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyServer.Listener = proxyListener
	proxyServer.Start()
	defer proxyServer.Close()

	_, proxyPort, err := stdnet.SplitHostPort(proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	const browserHost = "browser.test"
	wsHosts := []string{"ws-one.test", "ws-two.test"}
	browserOrigin := "http://" + stdnet.JoinHostPort(browserHost, proxyPort)

	startBrowserDialerChromium(t, chromePath, filepath.Join(t.TempDir(), "compat-profile"),
		"MAP "+browserHost+" 127.0.0.1, MAP "+wsHosts[0]+" 127.0.0.1, MAP "+wsHosts[1]+" 127.0.0.2",
		browserOrigin+"/bootstrap")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := DialPacketContext(ctx, http.MethodPost, browserOrigin+"/compat-204", nil, nil, []byte("payload")); err != nil {
		t.Fatalf("compatible ambient-cookie/204 request failed: %v", err)
	}
	select {
	case ok := <-ambientSeen:
		if !ok {
			t.Fatal("compatibility request did not retain the browser's ambient cookie")
		}
	case <-ctx.Done():
		t.Fatal("ambient-cookie observation timed out")
	}

	if err := DialPacketContext(ctx, http.MethodPost, browserOrigin+"/compat-redirect", nil, nil, []byte("payload")); err != nil {
		t.Fatalf("compatible redirect request failed: %v", err)
	}
	select {
	case ok := <-redirectSeen:
		if !ok {
			t.Fatal("redirect target did not retain the browser's ambient cookie")
		}
	case <-ctx.Done():
		t.Fatal("redirect observation timed out")
	}

	type streamDialResult struct {
		conn *websocket.Conn
		err  error
	}
	streamResult := make(chan streamDialResult, 1)
	go func() {
		conn, dialErr := DialGetContext(ctx, browserOrigin+"/compat-stream-404", nil, nil)
		streamResult <- streamDialResult{conn: conn, err: dialErr}
	}()
	select {
	case <-streamArrival:
	case <-ctx.Done():
		t.Fatal("compatible streaming GET did not reach its upstream")
	}
	var streamConn *websocket.Conn
	select {
	case result := <-streamResult:
		if result.err != nil {
			t.Fatalf("compatible streaming GET setup failed before response headers: %v", result.err)
		}
		streamConn = result.conn
	case <-time.After(time.Second):
		t.Fatal("compatible streaming GET waited for response headers instead of preserving its original acknowledgement")
	}
	releaseStream()
	_ = streamConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, streamPayload, err := streamConn.ReadMessage()
	if err != nil {
		t.Fatalf("read compatible non-200 stream body: %v", err)
	}
	if string(streamPayload) != "legacy-error-body" {
		t.Fatalf("compatible non-200 stream body = %q", streamPayload)
	}
	_ = streamConn.Close()

	cookieResults := make(chan error, 2)
	controlBaseline := controlUpgrades.Load()
	for _, value := range []string{"alpha", "beta"} {
		go func(cookieValue string) {
			cookieResults <- DialPacketContext(ctx, http.MethodPost, browserOrigin+"/explicit-cookie", nil,
				[]*http.Cookie{{Name: "temporary", Value: cookieValue}}, []byte("payload"))
		}(value)
	}
	firstExplicit := ""
	select {
	case firstExplicit = <-explicitCookieArrivals:
	case <-ctx.Done():
		t.Fatal("first explicit-cookie request timed out")
	}
	deadline := time.Now().Add(5 * time.Second)
	for controlUpgrades.Load() < controlBaseline+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if controlUpgrades.Load() < controlBaseline+2 {
		t.Fatal("browser did not assign both explicit-cookie tasks")
	}
	select {
	case second := <-explicitCookieArrivals:
		t.Fatalf("temporary-cookie writers overlapped before the first response: %q then %q", firstExplicit, second)
	case <-time.After(250 * time.Millisecond):
	}
	releaseFirstCookie()
	secondExplicit := ""
	select {
	case secondExplicit = <-explicitCookieArrivals:
	case <-ctx.Done():
		t.Fatal("second explicit-cookie request timed out")
	}
	seenCookies := map[string]bool{firstExplicit: true, secondExplicit: true}
	if !seenCookies["alpha"] || !seenCookies["beta"] {
		t.Fatalf("explicit cookie values were contaminated: first=%q second=%q", firstExplicit, secondExplicit)
	}
	for i := 0; i < 2; i++ {
		select {
		case cookieErr := <-cookieResults:
			if cookieErr != nil {
				t.Fatalf("explicit-cookie request failed: %v", cookieErr)
			}
		case <-ctx.Done():
			t.Fatal("explicit-cookie request completion timed out")
		}
	}
	if err := DialPacketContext(ctx, http.MethodPost, browserOrigin+"/explicit-cookie?check=1", nil, nil, []byte("payload")); err != nil {
		t.Fatalf("post-cookie compatibility request failed: %v", err)
	}
	select {
	case ok := <-postCookieSeen:
		if !ok {
			t.Fatal("temporary task cookie leaked or ambient cookie was lost after exclusive requests")
		}
	case <-ctx.Done():
		t.Fatal("post-cookie observation timed out")
	}

	results := make(chan *websocket.Conn, 2)
	resultErrors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(index int) {
			conn, dialErr := DialWSContext(ctx, "ws://"+stdnet.JoinHostPort(wsHosts[index], proxyPort)+"/parallel-ws", []byte(fmt.Sprintf("ed-%d", index)))
			if dialErr != nil {
				resultErrors <- dialErr
				return
			}
			results <- conn
		}(i)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-wsArrivals:
		case err := <-resultErrors:
			t.Fatalf("parallel Browser Dialer WebSocket failed before handshake release: %v", err)
		case <-time.After(8 * time.Second):
			t.Fatalf("Browser Dialer did not start both ordinary WebSocket handshakes (control upgrades: %d)", controlUpgrades.Load())
		}
	}
	releaseWebSockets()
	for i := 0; i < 2; i++ {
		select {
		case upgradeErr := <-wsUpgradeResults:
			if upgradeErr != nil {
				t.Fatalf("upstream WebSocket upgrade failed: %v", upgradeErr)
			}
		case <-ctx.Done():
			t.Fatal("upstream WebSocket upgrade result timed out")
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case conn := <-results:
			_ = conn.Close()
		case err := <-resultErrors:
			t.Fatalf("parallel Browser Dialer WebSocket failed: %v", err)
		case <-ctx.Done():
			t.Fatal("parallel Browser Dialer WebSocket completion timed out")
		}
	}

	// Exercise two same-address server generations without opening or refreshing
	// the compatibility page. Each generation deliberately rotates its token, so
	// the old page cannot recover. Its retries must back off and then stop instead
	// of continuing once per second forever.
	reloadControlBaseline := controlUpgrades.Load()
	if err := os.Setenv(platform.BrowserDialerStrict, "true"); err != nil {
		t.Fatal(err)
	}
	Reload()
	if err := os.Setenv(platform.BrowserDialerStrict, "false"); err != nil {
		t.Fatal(err)
	}
	Reload()

	// The production cap is 8 seconds, plus the one-second polling interval.
	// Twelve quiet seconds therefore prove that the page reached its finite failure
	// limit rather than merely sitting inside the longest backoff window.
	reloadControlFinal := waitForStableCounter(t, &controlUpgrades, 40*time.Second, 12*time.Second)
	if delta := reloadControlFinal - reloadControlBaseline; delta <= 0 || delta > 5 {
		t.Fatalf("Browser Dialer stale-token reconnect requests = %d, want 1..5 and then silence", delta)
	}

	// Switch the same listener generation to opt-in strict mode. The reverse
	// proxy continues targeting the same concrete address, while a fresh page
	// loaded through the literal loopback host receives strict tasks.
	browserAddr := listener.Addr().String()
	if err := os.Setenv(platform.BrowserDialerAddress, browserAddr); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv(platform.BrowserDialerStrict, "true"); err != nil {
		t.Fatal(err)
	}
	Reload()
	strictOrigin := "http://" + stdnet.JoinHostPort("127.0.0.1", proxyPort)
	startBrowserDialerChromium(t, chromePath, filepath.Join(t.TempDir(), "strict-profile"), "", strictOrigin+"/bootstrap")

	strictCtx, strictCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer strictCancel()
	if err := DialPacketContext(strictCtx, http.MethodPost, strictOrigin+"/strict-no-ambient", nil, nil, []byte("payload")); err != nil {
		t.Fatalf("strict credential-omission request failed: %v", err)
	}
	select {
	case ok := <-strictNoAmbientSeen:
		if !ok {
			t.Fatal("strict request retained an ambient browser cookie")
		}
	case <-strictCtx.Done():
		t.Fatal("strict credential observation timed out")
	}
	if err := DialPacketContext(strictCtx, http.MethodPost, strictOrigin+"/strict-204", nil, nil, []byte("payload")); err == nil {
		t.Fatal("strict Browser Dialer accepted HTTP 204")
	}
	if err := DialPacketContext(strictCtx, http.MethodPost, strictOrigin+"/strict-redirect", nil, nil, []byte("payload")); err == nil {
		t.Fatal("strict Browser Dialer followed an HTTP redirect")
	}
	if conn, err := DialGetContext(strictCtx, strictOrigin+"/strict-stream-404", nil, nil); err == nil {
		_ = conn.Close()
		t.Fatal("strict Browser Dialer accepted a non-200 streaming response")
	}
	if err := DialPacketContext(strictCtx, http.MethodPost, strictOrigin+"/strict-explicit", nil,
		[]*http.Cookie{{Name: "strictTemporary", Value: "strict-value"}}, []byte("payload")); err != nil {
		t.Fatalf("strict explicit-cookie request failed: %v", err)
	}
	select {
	case ok := <-strictExplicitSeen:
		if !ok {
			t.Fatal("strict request lost its explicit task cookie")
		}
	case <-strictCtx.Done():
		t.Fatal("strict explicit-cookie observation timed out")
	}

	hostRequest, err := http.NewRequestWithContext(strictCtx, http.MethodGet, strictOrigin+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	hostRequest.Host = stdnet.JoinHostPort("proxy.example", proxyPort)
	hostResponse, err := http.DefaultClient.Do(hostRequest)
	if err != nil {
		t.Fatal(err)
	}
	hostResponse.Body.Close()
	if hostResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("strict Browser Dialer alias status = %d, want 403", hostResponse.StatusCode)
	}
}

func startBrowserDialerChromium(t *testing.T, chromePath, profileDir, hostResolverRules, pageURL string) {
	t.Helper()
	arguments := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-gpu-sandbox",
		"--disable-software-rasterizer",
		"--disable-background-timer-throttling",
		"--disable-renderer-backgrounding",
		"--disable-extensions",
		"--disable-background-networking",
		"--no-proxy-server",
		"--no-first-run",
		"--no-default-browser-check",
		"--user-data-dir=" + profileDir,
	}
	if hostResolverRules != "" {
		arguments = append(arguments, "--host-resolver-rules="+hostResolverRules)
	}
	arguments = append(arguments, pageURL)
	command := exec.Command(chromePath, arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatalf("start Chromium: %v", err)
	}
	chromeDone := make(chan error, 1)
	go func() { chromeDone <- command.Wait() }()
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		select {
		case <-chromeDone:
		case <-time.After(5 * time.Second):
		}
	})
}

func reserveBrowserDialerAddress(t *testing.T) string {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func waitForStableCounter(t *testing.T, counter *atomic.Int32, timeout, stableFor time.Duration) int32 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := counter.Load()
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		current := counter.Load()
		if current != last {
			last = current
			stableSince = time.Now()
			continue
		}
		if time.Since(stableSince) >= stableFor {
			return current
		}
	}
	t.Fatalf("counter did not remain stable for %s", stableFor)
	return 0
}

func restoreBrowserDialerEnvironment(t *testing.T) {
	t.Helper()
	address, hadAddress := os.LookupEnv(platform.BrowserDialerAddress)
	strict, hadStrict := os.LookupEnv(platform.BrowserDialerStrict)
	t.Cleanup(func() {
		if hadAddress {
			_ = os.Setenv(platform.BrowserDialerAddress, address)
		} else {
			_ = os.Unsetenv(platform.BrowserDialerAddress)
		}
		if hadStrict {
			_ = os.Setenv(platform.BrowserDialerStrict, strict)
		} else {
			_ = os.Unsetenv(platform.BrowserDialerStrict)
		}
		Reload()
	})
}
