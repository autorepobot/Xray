package splithttp

import (
	"bytes"
	"compress/gzip"
	"context"
	stderrors "errors"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func newH1TestClient(t *testing.T, address string) *DefaultDialerClient {
	t.Helper()
	packetClient := newH1PacketClient(func(ctx context.Context) (xnet.Conn, error) {
		var dialer stdnet.Dialer
		return dialer.DialContext(ctx, "tcp", address)
	})
	t.Cleanup(func() {
		packetClient.Transport.(*http.Transport).CloseIdleConnections()
	})
	return &DefaultDialerClient{
		transportConfig: &Config{XPaddingBytes: &RangeConfig{From: 1, To: 1}},
		packetClient:    packetClient,
		httpVersion:     "1.1",
	}
}

func packetPayload(value string) buf.MultiBuffer {
	return buf.MultiBuffer{buf.FromBytes([]byte(value))}
}

func TestH1PacketPoolDoesNotImposeResponseHeaderTimeout(t *testing.T) {
	client := newH1PacketClient(func(context.Context) (xnet.Conn, error) {
		return nil, stderrors.New("unused")
	})
	transport := client.Transport.(*http.Transport)
	if transport.ResponseHeaderTimeout != 0 {
		t.Fatalf("H1 packet pool response header timeout = %v, want no absolute limit", transport.ResponseHeaderTimeout)
	}
}

func updateMaximum(maximum *atomic.Int32, value int32) {
	for {
		old := maximum.Load()
		if value <= old || maximum.CompareAndSwap(old, value) {
			return
		}
	}
}

func TestH1UploadPoolCapsConcurrentConnections(t *testing.T) {
	entered := make(chan struct{}, 20)
	release := make(chan struct{})
	var active, maximum, liveConnections, maximumConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		_, _ = io.Copy(io.Discard, request.Body)
		current := active.Add(1)
		updateMaximum(&maximum, current)
		entered <- struct{}{}
		<-release
		active.Add(-1)
		writer.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ stdnet.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			updateMaximum(&maximumConnections, liveConnections.Add(1))
		case http.StateClosed, http.StateHijacked:
			liveConnections.Add(-1)
		}
	}
	server.Start()
	defer server.Close()

	client := newH1TestClient(t, server.Listener.Addr().String())
	const requestCount = 20
	errorsByRequest := make(chan error, requestCount)
	var wg sync.WaitGroup
	wg.Add(requestCount)
	for i := range requestCount {
		go func(i int) {
			defer wg.Done()
			errorsByRequest <- client.PostPacket(context.Background(), server.URL+"/upload/", "session", string(rune('a'+i)), packetPayload("payload"))
		}(i)
	}

	for range h1MaxConnections {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("six H1 uploads did not reach the server")
		}
	}
	select {
	case <-entered:
		close(release)
		t.Fatal("a seventh H1 upload bypassed MaxConnsPerHost")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	close(errorsByRequest)
	for err := range errorsByRequest {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := maximum.Load(); got > h1MaxConnections {
		t.Fatalf("maximum concurrent H1 uploads = %d, want <= %d", got, h1MaxConnections)
	}
	if got := maximumConnections.Load(); got > h1MaxConnections {
		t.Fatalf("maximum live H1 TCP connections = %d, want <= %d", got, h1MaxConnections)
	}
}

func TestH1UploadPoolReusesSequentialConnection(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		_, _ = io.Copy(io.Discard, request.Body)
		writer.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ stdnet.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	client := newH1TestClient(t, server.Listener.Addr().String())
	for i := range 10 {
		if err := client.PostPacket(context.Background(), server.URL+"/upload/", "session", string(rune('a'+i)), packetPayload("payload")); err != nil {
			t.Fatal(err)
		}
	}
	if got := connections.Load(); got > 2 {
		t.Fatalf("10 sequential uploads used %d TCP connections, want <= 2", got)
	}
}

func TestH1UploadPoolReusesAllConnectionsAcrossBursts(t *testing.T) {
	entered := make(chan struct{}, 2*h1MaxConnections)
	gates := make(chan chan struct{}, 2*h1MaxConnections)
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		_, _ = io.Copy(io.Discard, request.Body)
		gate := <-gates
		entered <- struct{}{}
		<-gate
		writer.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ stdnet.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	client := newH1TestClient(t, server.Listener.Addr().String())

	runBurst := func(offset int) {
		t.Helper()
		gate := make(chan struct{})
		for range h1MaxConnections {
			gates <- gate
		}
		errorsByRequest := make(chan error, h1MaxConnections)
		for i := range h1MaxConnections {
			go func(i int) {
				errorsByRequest <- client.PostPacket(context.Background(), server.URL+"/upload/", "session", string(rune('a'+offset+i)), packetPayload("payload"))
			}(i)
		}
		for range h1MaxConnections {
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(gate)
				t.Fatal("H1 burst did not occupy all six connections")
			}
		}
		close(gate)
		for range h1MaxConnections {
			if err := <-errorsByRequest; err != nil {
				t.Fatal(err)
			}
		}
	}

	runBurst(0)
	if got := connections.Load(); got != h1MaxConnections {
		t.Fatalf("first burst opened %d connections, want %d", got, h1MaxConnections)
	}
	runBurst(h1MaxConnections)
	if got := connections.Load(); got != h1MaxConnections {
		t.Fatalf("two bursts opened %d connections, want the original %d reused", got, h1MaxConnections)
	}
}

func TestH1UploadPoolQueuedRequestIsCancelable(t *testing.T) {
	entered := make(chan struct{}, h1MaxConnections)
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		_, _ = io.Copy(io.Discard, request.Body)
		entered <- struct{}{}
		<-release
		writer.WriteHeader(http.StatusOK)
	}))
	server.Start()
	defer server.Close()
	client := newH1TestClient(t, server.Listener.Addr().String())

	var wg sync.WaitGroup
	wg.Add(h1MaxConnections)
	for i := range h1MaxConnections {
		go func(i int) {
			defer wg.Done()
			_ = client.PostPacket(context.Background(), server.URL+"/upload/", "session", string(rune('a'+i)), packetPayload("payload"))
		}(i)
	}
	for range h1MaxConnections {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("failed to occupy all H1 upload connections")
		}
	}

	queuedAtPool := make(chan struct{})
	var queuedOnce sync.Once
	queuedCtx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GetConn: func(string) { queuedOnce.Do(func() { close(queuedAtPool) }) },
	})
	queuedCtx, cancel := context.WithCancel(queuedCtx)
	result := make(chan error, 1)
	go func() {
		result <- client.PostPacket(queuedCtx, server.URL+"/upload/", "session", "queued", packetPayload("payload"))
	}()
	select {
	case <-queuedAtPool:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("seventh upload did not reach the H1 transport queue")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			close(release)
			t.Fatal("canceled queued upload unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("queued H1 upload did not observe context cancellation")
	}
	if client.IsClosed() {
		close(release)
		t.Fatal("canceling one session retired the shared H1 upload client")
	}
	close(release)
	wg.Wait()
}

func TestH1PacketUploadDoesNotInjectAcceptEncoding(t *testing.T) {
	acceptEncoding := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		_, _ = io.Copy(io.Discard, request.Body)
		acceptEncoding <- request.Header.Get("Accept-Encoding")
		writer.WriteHeader(http.StatusOK)
	}))
	server.Start()
	defer server.Close()

	client := newH1TestClient(t, server.Listener.Addr().String())
	if err := client.PostPacket(context.Background(), server.URL+"/upload/", "session", "0", packetPayload("payload")); err != nil {
		t.Fatal(err)
	}
	if got := <-acceptEncoding; got != "" {
		t.Fatalf("implicit Accept-Encoding = %q, want empty", got)
	}
}

func TestH1PacketUploadDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer target.Close()
	source := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	source.Start()
	defer source.Close()

	client := newH1TestClient(t, source.Listener.Addr().String())
	err := client.PostPacket(context.Background(), source.URL+"/upload/", "session", "0", packetPayload("payload"))
	if err == nil {
		t.Fatal("redirect response unexpectedly counted as a successful upload")
	}
	if redirected.Load() != 0 {
		t.Fatal("packet upload followed a redirect")
	}
}

func TestH1PacketFailureDoesNotPoisonSharedPool(t *testing.T) {
	wantErr := stderrors.New("one H1 socket failed")
	var calls atomic.Int32
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Body != nil {
			_, _ = io.Copy(io.Discard, request.Body)
			request.Body.Close()
		}
		if calls.Add(1) == 1 {
			return nil, wantErr
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		packetClient:    newHTTPClient(transport),
		httpVersion:     "1.1",
	}
	if err := client.PostPacket(context.Background(), "http://example.test/upload", "session-a", "0", packetPayload("first")); err == nil {
		t.Fatal("first H1 packet unexpectedly succeeded")
	}
	if client.IsClosed() {
		t.Fatal("one H1 socket failure poisoned the shared upload pool")
	}
	if err := client.PostPacket(context.Background(), "http://example.test/upload", "session-b", "0", packetPayload("second")); err != nil {
		t.Fatalf("unrelated H1 packet failed after pool recovered: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("H1 upload transport received %d requests, want 2", got)
	}
}

func TestH1PacketPoolCountsDownstreamAndUploadsTogether(t *testing.T) {
	downEntered := make(chan struct{}, 1)
	uploadEntered := make(chan struct{}, h1MaxConnections)
	releaseUploads := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(releaseUploads) }) }
	defer releaseAll()

	var liveConnections, maximumConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		if request.Method == http.MethodGet {
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			downEntered <- struct{}{}
			<-request.Context().Done()
			return
		}
		_, _ = io.Copy(io.Discard, request.Body)
		uploadEntered <- struct{}{}
		select {
		case <-releaseUploads:
			writer.WriteHeader(http.StatusOK)
		case <-request.Context().Done():
		}
	}))
	server.Config.ConnState = func(_ stdnet.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			updateMaximum(&maximumConnections, liveConnections.Add(1))
		case http.StateClosed, http.StateHijacked:
			liveConnections.Add(-1)
		}
	}
	server.Start()
	defer server.Close()

	client := newH1TestClient(t, server.Listener.Addr().String())
	down, _, _, err := client.openH1PacketDownWithTerminal(context.Background(), server.URL+"/down", "session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer down.Close()
	select {
	case <-downEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("H1 packet-down did not reach the shared pool")
	}

	errorsByRequest := make(chan error, h1MaxConnections)
	for i := range h1MaxConnections {
		go func(i int) {
			errorsByRequest <- client.PostPacket(context.Background(), server.URL+"/upload", "session", string(rune('a'+i)), packetPayload("payload"))
		}(i)
	}
	for range h1MaxConnections - 1 {
		select {
		case <-uploadEntered:
		case <-time.After(2 * time.Second):
			t.Fatal("five uploads did not use the connections left by one long downstream")
		}
	}
	select {
	case <-uploadEntered:
		t.Fatal("one downstream plus six uploads exceeded the shared six-connection cap")
	case <-time.After(150 * time.Millisecond):
	}
	if got := maximumConnections.Load(); got > h1MaxConnections {
		t.Fatalf("maximum live H1 packet-up connections = %d, want <= %d", got, h1MaxConnections)
	}

	// The pre-release checks above prove the shared client-side limit. Once the
	// downstream closes, net/http may release its MaxConnsPerHost slot and dial
	// the replacement before the server observes the old connection's FIN, so a
	// server-side historical ConnState maximum is no longer a valid cap metric.
	if err := down.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-uploadEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("closing packet-down did not release the sixth physical connection")
	}
	releaseAll()
	for range h1MaxConnections {
		if err := <-errorsByRequest; err != nil {
			t.Fatal(err)
		}
	}
}

func TestH1PacketDownPreservesCloseAndCompressionSemantics(t *testing.T) {
	type observedRequest struct {
		close          bool
		acceptEncoding string
	}
	observed := make(chan observedRequest, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observed <- observedRequest{close: request.Close, acceptEncoding: request.Header.Get("Accept-Encoding")}
		writer.Header().Set("Content-Encoding", "gzip")
		writer.WriteHeader(http.StatusOK)
		compressed := gzip.NewWriter(writer)
		_, _ = compressed.Write([]byte("downstream payload"))
		_ = compressed.Close()
	}))
	server.Start()
	defer server.Close()

	client := newH1TestClient(t, server.Listener.Addr().String())
	down, _, _, err := client.openH1PacketDownWithTerminal(context.Background(), server.URL+"/down", "session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer down.Close()
	payload, err := io.ReadAll(down)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("downstream payload")) {
		t.Fatalf("decompressed downstream = %q", payload)
	}
	request := <-observed
	if !request.close {
		t.Fatal("packet-down became reusable; want the original H1 Connection: close behavior")
	}
	if request.acceptEncoding != "gzip" {
		t.Fatalf("packet-down Accept-Encoding = %q, want the original implicit gzip", request.acceptEncoding)
	}
}

type h1PacketPathTestClient struct {
	packetCalls  atomic.Int32
	genericCalls atomic.Int32
	packetErr    error
}

var _ h1PacketDownDialerClient = (*h1PacketPathTestClient)(nil)

func (*h1PacketPathTestClient) IsClosed() bool { return false }

func (c *h1PacketPathTestClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, xnet.Addr, xnet.Addr, error) {
	c.genericCalls.Add(1)
	return io.NopCloser(strings.NewReader("")), &xnet.IPAddr{}, &xnet.IPAddr{}, nil
}

func (c *h1PacketPathTestClient) openH1PacketDownWithTerminal(context.Context, string, string, func(error)) (io.ReadCloser, xnet.Addr, xnet.Addr, error) {
	c.packetCalls.Add(1)
	if c.packetErr != nil {
		return nil, nil, nil, c.packetErr
	}
	return io.NopCloser(strings.NewReader("")), &xnet.IPAddr{}, &xnet.IPAddr{}, nil
}

func (*h1PacketPathTestClient) PostPacket(_ context.Context, _ string, _ string, _ string, payload buf.MultiBuffer) error {
	buf.ReleaseMulti(payload)
	return nil
}

func (*h1PacketPathTestClient) Close() error { return nil }

func installH1PacketTestManager(t *testing.T, destination xnet.Destination, memory *internet.MemoryStreamConfig, manager *XmuxManager) {
	t.Helper()
	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{{Destination: destination, MemoryStreamConfig: memory}: manager}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})
}

func TestH1PacketDownAdmissionReservesOneUploadConnection(t *testing.T) {
	destination := xnet.TCPDestination(xnet.DomainAddress("h1-admission.example"), 80)
	memory := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			Mode:               "packet-up",
			ScMaxEachPostBytes: &RangeConfig{From: 1024, To: 1024},
		},
	}
	fake := &h1PacketPathTestClient{}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })
	manager.enableH1PacketDownAdmission()
	installH1PacketTestManager(t, destination, memory, manager)

	connections := make([]io.Closer, 0, h1MaxPacketDownConnections)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range h1MaxPacketDownConnections {
		connection, err := Dial(context.Background(), destination, memory)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	if got := fake.packetCalls.Load(); got != h1MaxPacketDownConnections {
		t.Fatalf("packet-down calls = %d, want %d", got, h1MaxPacketDownConnections)
	}
	if got := len(manager.h1PacketDownSlots); got != h1MaxPacketDownConnections {
		t.Fatalf("held H1 packet-down admissions = %d, want %d", got, h1MaxPacketDownConnections)
	}
	manager.mu.Lock()
	requestBudgetBeforeQueue := manager.xmuxClients[0].LeftRequests.Load()
	manager.mu.Unlock()

	queuedCtx, cancel := context.WithCancel(context.Background())
	queuedResult := make(chan error, 1)
	go func() {
		_, err := Dial(queuedCtx, destination, memory)
		queuedResult <- err
	}()
	// The sixth Dial must be waiting before it reaches the client's stream path.
	time.Sleep(50 * time.Millisecond)
	if got := fake.packetCalls.Load(); got != h1MaxPacketDownConnections {
		cancel()
		t.Fatalf("sixth packet-down bypassed admission; calls = %d", got)
	}
	cancel()
	select {
	case err := <-queuedResult:
		if !stderrors.Is(err, context.Canceled) {
			t.Fatalf("queued H1 packet-down error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued H1 packet-down did not observe cancellation")
	}
	if got := len(manager.h1PacketDownSlots); got != h1MaxPacketDownConnections {
		t.Fatalf("canceled admission changed held slots to %d", got)
	}
	manager.mu.Lock()
	requestBudgetAfterCancel := manager.xmuxClients[0].LeftRequests.Load()
	manager.mu.Unlock()
	if requestBudgetAfterCancel != requestBudgetBeforeQueue {
		t.Fatalf("canceled queued Dial consumed hMaxRequestTimes: before=%d after=%d", requestBudgetBeforeQueue, requestBudgetAfterCancel)
	}

	if err := connections[0].Close(); err != nil {
		t.Fatal(err)
	}
	connections = connections[1:]
	connection, err := Dial(context.Background(), destination, memory)
	if err != nil {
		t.Fatal(err)
	}
	connections = append(connections, connection)
	if got := fake.packetCalls.Load(); got != h1MaxPacketDownConnections+1 {
		t.Fatalf("released admission did not wake the next packet-down; calls = %d", got)
	}
}

func TestH1PacketDownAdmissionReleasedOnSetupFailure(t *testing.T) {
	destination := xnet.TCPDestination(xnet.DomainAddress("h1-admission-failure.example"), 80)
	memory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Mode: "packet-up"},
	}
	wantErr := stderrors.New("packet-down setup failed")
	fake := &h1PacketPathTestClient{packetErr: wantErr}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })
	manager.enableH1PacketDownAdmission()
	installH1PacketTestManager(t, destination, memory, manager)

	if _, err := Dial(context.Background(), destination, memory); err == nil || (!stderrors.Is(err, wantErr) && !strings.Contains(err.Error(), wantErr.Error())) {
		t.Fatalf("Dial error = %v, want %v", err, wantErr)
	}
	if got := len(manager.h1PacketDownSlots); got != 0 {
		t.Fatalf("failed setup leaked %d H1 packet-down admissions", got)
	}
}

func TestH1NativeStreamModesBypassPacketPoolAndAdmission(t *testing.T) {
	tests := []struct {
		mode         string
		genericCalls int32
	}{
		{mode: "stream-one", genericCalls: 1},
		{mode: "stream-up", genericCalls: 2},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			destination := xnet.TCPDestination(xnet.DomainAddress(test.mode+".example"), 80)
			memory := &internet.MemoryStreamConfig{
				ProtocolName:     protocolName,
				ProtocolSettings: &Config{Mode: test.mode},
			}
			fake := &h1PacketPathTestClient{}
			manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })
			manager.enableH1PacketDownAdmission()
			installH1PacketTestManager(t, destination, memory, manager)

			connection, err := Dial(context.Background(), destination, memory)
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			if got := fake.packetCalls.Load(); got != 0 {
				t.Fatalf("native %s used H1 packet pool %d times", test.mode, got)
			}
			if got := fake.genericCalls.Load(); got != test.genericCalls {
				t.Fatalf("native %s generic stream calls = %d, want %d", test.mode, got, test.genericCalls)
			}
			if got := len(manager.h1PacketDownSlots); got != 0 {
				t.Fatalf("native %s consumed %d packet-down admissions", test.mode, got)
			}
		})
	}
}

func TestH1PacketDownLeavesIndependentDownloadManagerUnchanged(t *testing.T) {
	mainDestination := xnet.TCPDestination(xnet.DomainAddress("h1-main.example"), 80)
	downDestination := xnet.TCPDestination(xnet.DomainAddress("h1-down.example"), 80)
	downMemory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		Destination:      &downDestination,
	}
	mainMemory := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			Mode:             "packet-up",
			DownloadSettings: &internet.StreamConfig{},
		},
		DownloadSettings: downMemory,
	}
	mainFake := &h1PacketPathTestClient{}
	downFake := &h1PacketPathTestClient{}
	mainManager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return mainFake })
	downManager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return downFake })
	mainManager.enableH1PacketDownAdmission()
	downManager.enableH1PacketDownAdmission()

	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = map[dialerConf]*XmuxManager{
		{Destination: mainDestination, MemoryStreamConfig: mainMemory}: mainManager,
		{Destination: downDestination, MemoryStreamConfig: downMemory}: downManager,
	}
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()
	})

	connection, err := Dial(context.Background(), mainDestination, mainMemory)
	if err != nil {
		t.Fatal(err)
	}
	if got := downFake.packetCalls.Load(); got != 0 {
		connection.Close()
		t.Fatalf("independent download manager unexpectedly used packet pool %d times", got)
	}
	if got := downFake.genericCalls.Load(); got != 1 {
		connection.Close()
		t.Fatalf("independent download manager generic calls = %d, want 1", got)
	}
	if got := mainFake.packetCalls.Load(); got != 0 {
		connection.Close()
		t.Fatalf("upload manager unexpectedly opened %d packet-down streams", got)
	}
	if got := len(downManager.h1PacketDownSlots); got != 0 {
		connection.Close()
		t.Fatalf("independent download manager consumed %d packet-down admissions", got)
	}
	if got := len(mainManager.h1PacketDownSlots); got != 0 {
		connection.Close()
		t.Fatalf("upload manager consumed %d downstream admissions", got)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if got := len(downManager.h1PacketDownSlots); got != 0 {
		t.Fatalf("closing split-route packet-up changed download admissions to %d", got)
	}
}

func TestH1CustomManagerDoesNotEnablePacketAdmission(t *testing.T) {
	destination := xnet.TCPDestination(xnet.DomainAddress("h1-custom.example"), 80)
	memory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Mode: "packet-up"},
	}
	fake := &h1PacketPathTestClient{}
	manager := NewXmuxManagerForHTTPVersion(nil, "1.1", func() XmuxConn { return fake })
	installH1PacketTestManager(t, destination, memory, manager)

	connections := make([]io.Closer, 0, h1MaxConnections)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range h1MaxConnections {
		connection, err := Dial(context.Background(), destination, memory)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	if manager.hasH1PacketDownAdmission() {
		t.Fatal("public/custom H1 manager unexpectedly enabled packet admission")
	}
	if got := fake.packetCalls.Load(); got != 0 {
		t.Fatalf("custom H1 manager used private packet path %d times", got)
	}
	if got := fake.genericCalls.Load(); got != h1MaxConnections {
		t.Fatalf("custom H1 manager generic calls = %d, want %d", got, h1MaxConnections)
	}
}

func TestH1PacketUpDialMaintainsFivePlusOneConnectionBudget(t *testing.T) {
	downEntered := make(chan struct{}, h1MaxConnections)
	postEntered := make(chan struct{}, 1)
	var liveConnections, maximumConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		if request.Method == http.MethodGet {
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			downEntered <- struct{}{}
			<-request.Context().Done()
			return
		}
		_, _ = io.Copy(io.Discard, request.Body)
		postEntered <- struct{}{}
		writer.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ stdnet.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			updateMaximum(&maximumConnections, liveConnections.Add(1))
		case http.StateClosed, http.StateHijacked:
			liveConnections.Add(-1)
		}
	}
	server.Start()
	defer server.Close()
	defer server.CloseClientConnections()

	address := server.Listener.Addr().(*stdnet.TCPAddr)
	destination := xnet.TCPDestination(xnet.IPAddress(address.IP), xnet.Port(address.Port))
	memory := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			Mode:               "packet-up",
			ScMaxEachPostBytes: &RangeConfig{From: 1, To: 1},
			XPaddingBytes:      &RangeConfig{From: 1, To: 1},
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

	type writeCloser interface {
		io.Writer
		io.Closer
	}
	connections := make([]writeCloser, 0, h1MaxPacketDownConnections+1)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range h1MaxPacketDownConnections {
		connection, err := Dial(context.Background(), destination, memory)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
		select {
		case <-downEntered:
		case <-time.After(2 * time.Second):
			t.Fatal("packet-up Dial did not establish its H1 downstream")
		}
	}

	queuedResult := make(chan struct {
		connection writeCloser
		err        error
	}, 1)
	go func() {
		connection, err := Dial(context.Background(), destination, memory)
		queuedResult <- struct {
			connection writeCloser
			err        error
		}{connection: connection, err: err}
	}()
	select {
	case <-downEntered:
		t.Fatal("sixth packet-up downstream bypassed the five-session admission")
	case result := <-queuedResult:
		if result.connection != nil {
			_ = result.connection.Close()
		}
		t.Fatalf("sixth packet-up Dial returned before a slot was released: %v", result.err)
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := connections[0].Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-postEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("packet POST could not use the reserved sixth H1 connection")
	}
	globalDialerAccess.Lock()
	manager := globalDialerMap[dialerConf{Destination: destination, MemoryStreamConfig: memory}]
	globalDialerAccess.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		manager.mu.Lock()
		inFlight := int32(0)
		for _, client := range manager.xmuxClients {
			inFlight += client.InFlight.Load()
		}
		manager.mu.Unlock()
		if inFlight == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("packet POST acknowledgement did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if got := maximumConnections.Load(); got > h1MaxConnections {
		t.Fatalf("end-to-end H1 packet-up opened %d live connections, want <= %d", got, h1MaxConnections)
	}

	// From this point the client may release the closed connection slot before
	// the server observes its FIN. The strict pre-release check above is the
	// meaningful MaxConnsPerHost assertion; a historical server-side maximum is
	// not valid across the replacement.
	if err := connections[0].Close(); err != nil {
		t.Fatal(err)
	}
	connections = connections[1:]
	select {
	case result := <-queuedResult:
		if result.err != nil {
			t.Fatal(result.err)
		}
		connections = append(connections, result.connection)
	case <-time.After(2 * time.Second):
		t.Fatal("releasing one downstream did not admit the queued packet-up Dial")
	}
	select {
	case <-downEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("admitted packet-up Dial did not establish its downstream")
	}
}

func TestH1PacketDownEOFReleasesAdmission(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	server.Start()
	defer server.Close()

	address := server.Listener.Addr().(*stdnet.TCPAddr)
	destination := xnet.TCPDestination(xnet.IPAddress(address.IP), xnet.Port(address.Port))
	memory := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{Mode: "packet-up"},
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

	connection, err := Dial(context.Background(), destination, memory)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	globalDialerAccess.Lock()
	manager := globalDialerMap[dialerConf{Destination: destination, MemoryStreamConfig: memory}]
	globalDialerAccess.Unlock()
	if manager == nil || len(manager.h1PacketDownSlots) != 1 {
		t.Fatal("successful H1 packet-down did not hold one admission")
	}

	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); !stderrors.Is(err, io.EOF) {
		t.Fatalf("closed packet-down Read error = %v, want EOF", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(manager.h1PacketDownSlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("remote packet-down EOF leaked its admission")
		}
		time.Sleep(time.Millisecond)
	}
}
