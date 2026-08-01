package splithttp_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

type fakeRoundTripper struct {
	closed     atomic.Bool
	closeCount atomic.Int32
}

func (f *fakeRoundTripper) IsClosed() bool {
	return f.closed.Load()
}

func (f *fakeRoundTripper) Close() error {
	f.closeCount.Add(1)
	f.closed.Store(true)
	return nil
}

func newTestManager(config *XmuxConfig, version string) *XmuxManager {
	return NewXmuxManagerForHTTPVersion(config, version, func() XmuxConn {
		return &fakeRoundTripper{}
	})
}

func TestAdaptiveConcurrencyWithConnectionCap(t *testing.T) {
	manager := newTestManager(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 2, To: 2},
		MaxConnections: &RangeConfig{From: 3, To: 3},
	}, "2")

	leasing := make([]*XmuxLease, 10)
	clients := make(map[*XmuxClient]struct{})
	for i := range leasing {
		leasing[i] = manager.AcquireSession(context.Background())
		clients[leasing[i].Client()] = struct{}{}
	}
	if len(clients) != 3 {
		t.Fatalf("adaptive scheduler created %d clients, want 3", len(clients))
	}
	for _, lease := range leasing {
		lease.Release()
	}
}

func TestExplicitMaxConnectionsOnlyStillEagerlyFills(t *testing.T) {
	manager := newTestManager(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: -1, To: -1},
		MaxConnections: &RangeConfig{From: 4, To: 4},
	}, "2")

	clients := make(map[*XmuxClient]struct{})
	leases := make([]*XmuxLease, 8)
	for i := range leases {
		leases[i] = manager.AcquireSession(context.Background())
		clients[leases[i].Client()] = struct{}{}
	}
	if len(clients) != 4 {
		t.Fatalf("maxConnections-only scheduler created %d clients, want 4", len(clients))
	}
	for _, lease := range leases {
		lease.Release()
	}
}

func TestExplicitMaxConcurrencyOnlyCanExpand(t *testing.T) {
	manager := newTestManager(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 2, To: 2},
		MaxConnections: &RangeConfig{From: -1, To: -1},
	}, "2")

	clients := make(map[*XmuxClient]struct{})
	leases := make([]*XmuxLease, 64)
	for i := range leases {
		leases[i] = manager.AcquireSession(context.Background())
		clients[leases[i].Client()] = struct{}{}
	}
	if len(clients) != 32 {
		t.Fatalf("maxConcurrency-only scheduler created %d clients, want 32", len(clients))
	}
	for _, lease := range leases {
		lease.Release()
	}
}

func TestH1AutoUsesSingleXmuxClient(t *testing.T) {
	manager := newTestManager(nil, "1.1")
	clients := make(map[*XmuxClient]struct{})
	leases := make([]*XmuxLease, 64)
	for i := range leases {
		leases[i] = manager.AcquireSession(context.Background())
		clients[leases[i].Client()] = struct{}{}
	}
	if len(clients) != 1 {
		t.Fatalf("H1 auto created %d Xmux clients, want 1", len(clients))
	}
	for _, lease := range leases {
		lease.Release()
	}
}

func TestAcquireSessionReservesAtomically(t *testing.T) {
	manager := newTestManager(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 8, To: 8},
		MaxConnections: &RangeConfig{From: 3, To: 3},
	}, "2")

	const count = 100
	leasing := make([]*XmuxLease, count)
	var wg sync.WaitGroup
	wg.Add(count)
	for i := range leasing {
		go func(i int) {
			defer wg.Done()
			leasing[i] = manager.AcquireSession(context.Background())
		}(i)
	}
	wg.Wait()

	clients := make(map[*XmuxClient]struct{})
	var running int32
	for _, lease := range leasing {
		clients[lease.Client()] = struct{}{}
	}
	for client := range clients {
		running += client.Running.Load()
	}
	if len(clients) != 3 {
		t.Fatalf("concurrent acquire created %d clients, want 3", len(clients))
	}
	if running != count {
		t.Fatalf("total Running = %d, want %d", running, count)
	}
	for _, lease := range leasing {
		lease.Release()
		lease.Release() // idempotence
	}
	for client := range clients {
		if got := client.Running.Load(); got != 0 {
			t.Fatalf("Running after release = %d, want 0", got)
		}
	}
}

func TestAcquireSessionRequestBudgetIsAtomic(t *testing.T) {
	manager := newTestManager(&XmuxConfig{
		MaxConcurrency:   &RangeConfig{From: 100, To: 100},
		MaxConnections:   &RangeConfig{From: 1, To: 1},
		HMaxRequestTimes: &RangeConfig{From: 8, To: 8},
	}, "2")

	const count = 100
	leases := make([]*XmuxLease, count)
	var wg sync.WaitGroup
	wg.Add(count)
	for i := range leases {
		go func(i int) {
			defer wg.Done()
			leases[i] = manager.AcquireSessionWithRequests(context.Background(), 1)
		}(i)
	}
	wg.Wait()

	clients := make(map[*XmuxClient]struct{})
	for _, lease := range leases {
		if lease == nil {
			t.Fatal("request-budget acquire unexpectedly returned nil")
		}
		clients[lease.Client()] = struct{}{}
	}
	if len(clients) != 13 {
		t.Fatalf("100 requests with hMax=8 used %d clients, want 13", len(clients))
	}
	for client := range clients {
		if remaining := client.LeftRequests.Load(); remaining < 0 {
			t.Fatalf("request budget underflowed to %d", remaining)
		}
	}
	for _, lease := range leases {
		lease.Release()
	}
}

func TestAcquireSessionTreatsInitialStreamsAsIndivisible(t *testing.T) {
	manager := newTestManager(&XmuxConfig{
		MaxConcurrency:   &RangeConfig{From: 100, To: 100},
		MaxConnections:   &RangeConfig{From: 1, To: 1},
		HMaxRequestTimes: &RangeConfig{From: 1, To: 1},
	}, "2")
	first := manager.AcquireSessionWithRequests(context.Background(), 2)
	second := manager.AcquireSessionWithRequests(context.Background(), 2)
	if first == nil || second == nil {
		t.Fatal("two-stream session acquisition returned nil")
	}
	if first.Client() == second.Client() {
		t.Fatal("exhausted two-stream client was reused")
	}
	if first.Client().LeftRequests.Load() != 0 || second.Client().LeftRequests.Load() != 0 {
		t.Fatal("indivisible initial stream reservation did not consume the fresh-client budget")
	}
	first.Release()
	second.Release()
}

func TestExhaustedClientRetiresWithoutAnotherManagerCall(t *testing.T) {
	tests := []struct {
		name   string
		config *XmuxConfig
		slots  int32
	}{
		{
			name: "hMaxRequestTimes",
			config: &XmuxConfig{
				MaxConcurrency:   &RangeConfig{From: -1, To: -1},
				MaxConnections:   &RangeConfig{From: 1, To: 1},
				HMaxRequestTimes: &RangeConfig{From: 1, To: 1},
			},
			slots: 1,
		},
		{
			name: "cMaxReuseTimes",
			config: &XmuxConfig{
				MaxConcurrency: &RangeConfig{From: -1, To: -1},
				MaxConnections: &RangeConfig{From: 1, To: 1},
				CMaxReuseTimes: &RangeConfig{From: 1, To: 1},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := newTestManager(test.config, "2")
			lease := manager.AcquireSessionWithRequests(context.Background(), test.slots)
			client := lease.Client()
			fake := client.XmuxConn.(*fakeRoundTripper)
			if !client.Retired.Load() {
				t.Fatal("client was not retired when its final reuse budget was consumed")
			}
			if fake.closed.Load() {
				t.Fatal("client closed before its active session drained")
			}
			lease.Release()
			if !fake.closed.Load() || fake.closeCount.Load() != 1 {
				t.Fatalf("drained client close state=%v count=%d, want true/1", fake.closed.Load(), fake.closeCount.Load())
			}
		})
	}
}

func TestPacketLeaseProtectsRetiredClient(t *testing.T) {
	manager := newTestManager(&XmuxConfig{
		MaxConcurrency:   &RangeConfig{From: 1, To: 1},
		MaxConnections:   &RangeConfig{From: 1, To: 1},
		HMaxRequestTimes: &RangeConfig{From: 1, To: 1},
	}, "2")

	session := manager.AcquireSession(context.Background())
	oldClient := session.Client()
	request := manager.BorrowPacket(context.Background(), oldClient)
	if request == nil || request.Client() != oldClient {
		t.Fatal("first packet did not borrow the session client")
	}
	if got := oldClient.Running.Load(); got != 1 {
		t.Fatalf("packet borrow changed Running to %d", got)
	}

	nextRequest := manager.BorrowPacket(context.Background(), oldClient)
	if nextRequest == nil || nextRequest.Client() == oldClient {
		t.Fatal("request budget exhaustion did not rotate the client")
	}
	if !oldClient.Retired.Load() {
		t.Fatal("exhausted client was not retired")
	}

	session.Release()
	fake := oldClient.XmuxConn.(*fakeRoundTripper)
	if fake.closed.Load() {
		t.Fatal("retired client closed while a packet request was in flight")
	}
	request.Release()
	if !fake.closed.Load() || fake.closeCount.Load() != 1 {
		t.Fatalf("retired client close state = %v, closes = %d; want true/1", fake.closed.Load(), fake.closeCount.Load())
	}
	request.Release()
	if fake.closeCount.Load() != 1 {
		t.Fatalf("duplicate request release closed client %d times", fake.closeCount.Load())
	}
	nextRequest.Release()
}

func TestPacketOnlyReplacementRemainsPreferred(t *testing.T) {
	created := atomic.Int32{}
	manager := NewXmuxManagerForHTTPVersion(&XmuxConfig{
		MaxConcurrency:   &RangeConfig{From: -1, To: -1},
		MaxConnections:   &RangeConfig{From: 2, To: 2},
		HMaxRequestTimes: &RangeConfig{From: 2, To: 2},
	}, "2", func() XmuxConn {
		created.Add(1)
		return &fakeRoundTripper{}
	})

	session := manager.AcquireSession(context.Background())
	original := session.Client()
	for range 2 {
		request := manager.BorrowPacket(context.Background(), original)
		if request == nil || request.Client() != original {
			t.Fatal("request budget was not consumed on the original session client")
		}
		request.Release()
	}

	replacementRequest := manager.BorrowPacket(context.Background(), original)
	if replacementRequest == nil || replacementRequest.Client() == original {
		t.Fatal("exhausted session client did not rotate to a packet-only replacement")
	}
	replacement := replacementRequest.Client()
	replacementRequest.Release()

	next := manager.BorrowPacket(context.Background(), replacement)
	if next == nil || next.Client() != replacement {
		t.Fatal("active packet-only replacement did not remain the preferred client")
	}
	if got := created.Load(); got != 2 {
		t.Fatalf("preferred packet reuse created %d transports, want 2", got)
	}
	next.Release()
	session.Release()
}

func TestCMaxReuseTimes(t *testing.T) {
	manager := newTestManager(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: -1, To: -1},
		MaxConnections: &RangeConfig{From: -1, To: -1},
		CMaxReuseTimes: &RangeConfig{From: 2, To: 2},
	}, "2")

	clients := make(map[*XmuxClient]struct{})
	for range 64 {
		lease := manager.AcquireSession(context.Background())
		clients[lease.Client()] = struct{}{}
		lease.Release()
	}
	if len(clients) != 32 {
		t.Fatalf("cMaxReuseTimes created %d clients, want 32", len(clients))
	}
}

type blockingCloseConn struct {
	closed        atomic.Bool
	closeEntered  chan struct{}
	closeFinished chan struct{}
	allowClose    chan struct{}
	enterOnce     sync.Once
	allowOnce     sync.Once
}

func newBlockingCloseConn() *blockingCloseConn {
	return &blockingCloseConn{
		closeEntered:  make(chan struct{}),
		closeFinished: make(chan struct{}),
		allowClose:    make(chan struct{}),
	}
}

func (c *blockingCloseConn) IsClosed() bool { return c.closed.Load() }
func (c *blockingCloseConn) Close() error {
	c.enterOnce.Do(func() { close(c.closeEntered) })
	<-c.allowClose
	c.closed.Store(true)
	close(c.closeFinished)
	return nil
}

func (c *blockingCloseConn) unblock() {
	c.allowOnce.Do(func() { close(c.allowClose) })
}

func TestRetiredClientRejectsBorrowAfterCloseStarts(t *testing.T) {
	blocked := newBlockingCloseConn()
	created := atomic.Int32{}
	manager := NewXmuxManagerForHTTPVersion(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 1, To: 1},
		MaxConnections: &RangeConfig{From: 1, To: 1},
		CMaxReuseTimes: &RangeConfig{From: 1, To: 1},
	}, "2", func() XmuxConn {
		if created.Add(1) == 1 {
			return blocked
		}
		return &fakeRoundTripper{}
	})

	session := manager.AcquireSession(context.Background())
	oldClient := session.Client()
	nextSession := manager.AcquireSession(context.Background()) // retires old by cMax
	released := make(chan struct{})
	go func() {
		session.Release()
		close(released)
	}()
	select {
	case <-blocked.closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("retired client did not start closing")
	}

	request := manager.BorrowPacket(context.Background(), oldClient)
	if request == nil {
		blocked.unblock()
		t.Fatal("fallback packet borrow returned nil")
	}
	if request.Client() == oldClient {
		blocked.unblock()
		t.Fatal("packet was admitted after transport close had started")
	}
	request.Release()
	nextSession.Release()
	blocked.unblock()
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked close did not finish")
	}
}

func TestSlowTransportCloseDoesNotHoldManagerLock(t *testing.T) {
	blocked := newBlockingCloseConn()
	created := atomic.Int32{}
	manager := NewXmuxManagerForHTTPVersion(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: -1, To: -1},
		MaxConnections: &RangeConfig{From: 1, To: 1},
	}, "2", func() XmuxConn {
		if created.Add(1) == 1 {
			return blocked
		}
		return &fakeRoundTripper{}
	})
	first := manager.AcquireSession(context.Background())
	first.Release()
	blocked.closed.Store(true)

	secondResult := make(chan *XmuxLease, 1)
	go func() { secondResult <- manager.AcquireSession(context.Background()) }()
	select {
	case <-blocked.closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("unhealthy transport did not enter Close")
	}
	var second *XmuxLease
	select {
	case second = <-secondResult:
	case <-time.After(2 * time.Second):
		blocked.unblock()
		t.Fatal("replacement lease waited for the old transport to close")
	}

	thirdResult := make(chan *XmuxLease, 1)
	go func() { thirdResult <- manager.AcquireSession(context.Background()) }()
	var third *XmuxLease
	select {
	case third = <-thirdResult:
	case <-time.After(2 * time.Second):
		blocked.unblock()
		t.Fatal("slow transport Close held the manager lock")
	}
	blocked.unblock()
	second.Release()
	third.Release()
	select {
	case <-blocked.closeFinished:
	case <-time.After(2 * time.Second):
		t.Fatal("slow transport Close did not finish")
	}
}
