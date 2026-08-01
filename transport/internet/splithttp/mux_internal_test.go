package splithttp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type boundedCloseConn struct {
	closed      atomic.Bool
	entered     chan struct{}
	release     chan struct{}
	finished    chan struct{}
	releaseOnce sync.Once
}

func (c *boundedCloseConn) unblock() {
	c.releaseOnce.Do(func() { close(c.release) })
}

func newBoundedCloseConn() *boundedCloseConn {
	return &boundedCloseConn{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan struct{}),
	}
}

func (c *boundedCloseConn) IsClosed() bool { return c.closed.Load() }

func (c *boundedCloseConn) Close() error {
	close(c.entered)
	<-c.release
	c.closed.Store(true)
	close(c.finished)
	return nil
}

func waitForAsyncCloseSlots(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(xmuxAsyncCloseSlots) != want {
		if time.Now().After(deadline) {
			t.Fatalf("active cleanup slots = %d, want %d", len(xmuxAsyncCloseSlots), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBlockedAsyncTransportClosesHaveBoundedConcurrency(t *testing.T) {
	waitForAsyncCloseSlots(t, 0)
	connections := make([]*boundedCloseConn, maxConcurrentAsyncXmuxCloses+1)
	clients := make([]*XmuxClient, len(connections))
	for i := range connections {
		connections[i] = newBoundedCloseConn()
		clients[i] = &XmuxClient{XmuxConn: connections[i]}
	}
	defer func() {
		for _, connection := range connections {
			connection.unblock()
		}
	}()

	submitted := make(chan struct{})
	go func() {
		closeXmuxClients(clients)
		close(submitted)
	}()
	for i := 0; i < maxConcurrentAsyncXmuxCloses; i++ {
		select {
		case <-connections[i].entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("close %d did not enter", i)
		}
	}
	select {
	case <-connections[maxConcurrentAsyncXmuxCloses].entered:
		t.Fatal("cleanup exceeded its concurrency bound")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-submitted:
		t.Fatal("cleanup submission did not apply backpressure at its bound")
	default:
	}

	connections[0].unblock()
	select {
	case <-connections[maxConcurrentAsyncXmuxCloses].entered:
	case <-time.After(2 * time.Second):
		t.Fatal("queued cleanup did not start when capacity became available")
	}
	select {
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup submission did not resume")
	}

	for i := 1; i < len(connections); i++ {
		connections[i].unblock()
	}
	for i, connection := range connections {
		select {
		case <-connection.finished:
		case <-time.After(2 * time.Second):
			t.Fatalf("close %d did not finish", i)
		}
	}
	waitForAsyncCloseSlots(t, 0)
}

type openXmuxConn struct{}

func (*openXmuxConn) IsClosed() bool { return false }

func TestConcurrencyRangeIsSampledOncePerManager(t *testing.T) {
	manager := NewXmuxManagerForHTTPVersion(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 32, To: 64},
		MaxConnections: &RangeConfig{From: -1, To: -1},
	}, "2", func() XmuxConn { return &openXmuxConn{} })

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.targetConcurrency < 32 || manager.targetConcurrency >= 64 {
		t.Fatalf("manager concurrency sample = %d, want [32,64)", manager.targetConcurrency)
	}
	for range 16 {
		client := manager.newXmuxClientLocked(0)
		if client.targetConcurrency != manager.targetConcurrency {
			t.Fatalf("client concurrency = %d, want manager sample %d", client.targetConcurrency, manager.targetConcurrency)
		}
	}
}

type affinityTestConn struct {
	closed     atomic.Bool
	closeCount atomic.Int32
}

func (c *affinityTestConn) IsClosed() bool { return c.closed.Load() }
func (c *affinityTestConn) Close() error {
	c.closeCount.Add(1)
	c.closed.Store(true)
	return nil
}

func TestPacketOnlyReplacementKeepsAffinityAcrossCMaxRetirement(t *testing.T) {
	var connections []*affinityTestConn
	manager := NewXmuxManagerForHTTPVersion(&XmuxConfig{
		MaxConcurrency:   &RangeConfig{From: -1, To: -1},
		MaxConnections:   &RangeConfig{From: 2, To: 2},
		CMaxReuseTimes:   &RangeConfig{From: 1, To: 1},
		HMaxRequestTimes: &RangeConfig{From: 2, To: 2},
	}, "2", func() XmuxConn {
		connection := &affinityTestConn{}
		connections = append(connections, connection)
		return connection
	})

	session := manager.AcquireSession(context.Background())
	original := session.Client()
	for range 2 {
		request, affinity := manager.borrowPacketWithAffinity(context.Background(), original)
		if request == nil || request.Client() != original || affinity != nil {
			t.Fatal("original session client did not serve its own packet budget")
		}
		request.Release()
	}

	request, affinity := manager.borrowPacketWithAffinity(context.Background(), original)
	if request == nil || request.Client() == original || affinity == nil {
		t.Fatal("packet rotation did not return a pinned replacement")
	}
	replacement := request.Client()
	if !replacement.Retired.Load() {
		t.Fatal("cMax=1 replacement was not retired from the active pool")
	}
	request.Release()
	if replacement.XmuxConn.(*affinityTestConn).closed.Load() {
		t.Fatal("retired replacement closed while its upload flow held affinity")
	}

	next, unexpectedAffinity := manager.borrowPacketWithAffinity(context.Background(), replacement)
	if next == nil || next.Client() != replacement || unexpectedAffinity != nil {
		t.Fatal("the next packet did not reuse its retired affinity client")
	}
	if len(connections) != 2 {
		t.Fatalf("two replacement packets created %d transports, want 2", len(connections))
	}
	next.Release()

	rotated, nextAffinity := manager.borrowPacketWithAffinity(context.Background(), replacement)
	if rotated == nil || rotated.Client() == replacement || nextAffinity == nil {
		t.Fatal("hMax exhaustion did not rotate to a newly pinned client")
	}
	nextReplacement := rotated.Client()
	rotated.Release()
	affinity.Release()
	if got := replacement.XmuxConn.(*affinityTestConn).closeCount.Load(); got != 1 {
		t.Fatalf("released old affinity closed its client %d times, want 1", got)
	}

	nextAffinity.Release()
	session.Release()
	clients := []*XmuxClient{original, replacement, nextReplacement}
	for i, client := range clients {
		if client.Running.Load() != 0 || client.InFlight.Load() != 0 || client.packetAffinities.Load() != 0 {
			t.Fatalf("client %d leaked counters: Running=%d InFlight=%d affinity=%d", i,
				client.Running.Load(), client.InFlight.Load(), client.packetAffinities.Load())
		}
		if got := client.XmuxConn.(*affinityTestConn).closeCount.Load(); got != 1 {
			t.Fatalf("client %d closed %d times, want 1", i, got)
		}
	}
}

func TestPacketAffinitiesCountTowardAdaptiveLoad(t *testing.T) {
	manager := NewXmuxManagerForHTTPVersion(&XmuxConfig{
		MaxConcurrency:   &RangeConfig{From: 2, To: 2},
		MaxConnections:   &RangeConfig{From: 3, To: 3},
		HMaxRequestTimes: &RangeConfig{From: 100, To: 100},
	}, "2", func() XmuxConn { return &affinityTestConn{} })

	const sessionCount = 8
	sessions := make([]*XmuxLease, sessionCount)
	for i := range sessions {
		sessions[i] = manager.AcquireSession(context.Background())
	}

	// Expire every original client together. Each session's next packet must
	// rotate to a packet-only client and pin that replacement for future POSTs.
	manager.mu.Lock()
	for _, client := range manager.xmuxClients {
		client.UnreusableAt = time.Now().Add(-time.Second)
	}
	manager.mu.Unlock()

	requests := make([]*XmuxLease, 0, sessionCount)
	affinities := make([]*XmuxLease, 0, sessionCount)
	replacements := make(map[*XmuxClient]struct{})
	for _, session := range sessions {
		request, affinity := manager.borrowPacketWithAffinity(context.Background(), session.Client())
		if request == nil || affinity == nil {
			t.Fatal("expired session did not rotate to a pinned replacement")
		}
		requests = append(requests, request)
		affinities = append(affinities, affinity)
		replacements[request.Client()] = struct{}{}
	}
	if len(replacements) != 3 {
		t.Fatalf("%d rotated packet flows used %d replacements, want 3", sessionCount, len(replacements))
	}

	for _, request := range requests {
		request.Release()
	}
	for _, affinity := range affinities {
		affinity.Release()
	}
	for _, session := range sessions {
		session.Release()
	}
}

func TestPacketAffinityStateClosesAdmissionAndTransfersOwnership(t *testing.T) {
	first := &XmuxLease{}
	second := &XmuxLease{}
	var state packetAffinityState
	if previous, ok := state.install(first); !ok || previous != nil {
		t.Fatal("first affinity install failed")
	}
	if previous, ok := state.install(nil); !ok || previous != nil {
		t.Fatal("preferred-client reuse unexpectedly changed affinity")
	}
	if previous, ok := state.install(second); !ok || previous != first {
		t.Fatal("affinity replacement did not transfer the old lease")
	}
	if current := state.closeAdmission(); current != second {
		t.Fatal("closing admission did not return the current affinity")
	}
	if current := state.closeAdmission(); current != nil {
		t.Fatal("closing admission twice returned an affinity twice")
	}
	if _, ok := state.install(nil); ok {
		t.Fatal("closed affinity gate accepted preferred-client reuse")
	}
	if _, ok := state.install(&XmuxLease{}); ok {
		t.Fatal("closed affinity gate accepted a new pin")
	}
}

func TestAsyncMultiLeaseReleaseReturnsAllCountersBeforeClose(t *testing.T) {
	waitForAsyncCloseSlots(t, 0)
	connections := []*boundedCloseConn{newBoundedCloseConn(), newBoundedCloseConn()}
	sessionClient := &XmuxClient{XmuxConn: connections[0]}
	sessionClient.Running.Store(1)
	sessionClient.Retired.Store(true)
	affinityClient := &XmuxClient{XmuxConn: connections[1]}
	affinityClient.packetAffinities.Store(1)
	affinityClient.Retired.Store(true)

	releaseXmuxLeasesAsync(
		&XmuxLease{client: sessionClient, kind: xmuxSessionLease},
		&XmuxLease{client: affinityClient, kind: xmuxPacketAffinityLease},
	)
	if sessionClient.Running.Load() != 0 || affinityClient.packetAffinities.Load() != 0 {
		t.Fatalf("lease counters were not returned before Close: Running=%d affinity=%d",
			sessionClient.Running.Load(), affinityClient.packetAffinities.Load())
	}
	for i, connection := range connections {
		select {
		case <-connection.entered:
		case <-time.After(2 * time.Second):
			for _, pending := range connections {
				pending.unblock()
			}
			t.Fatalf("close %d did not start", i)
		}
	}
	for _, connection := range connections {
		connection.unblock()
	}
	for i, connection := range connections {
		select {
		case <-connection.finished:
		case <-time.After(2 * time.Second):
			t.Fatalf("close %d did not finish", i)
		}
	}
	waitForAsyncCloseSlots(t, 0)
}
