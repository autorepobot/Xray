package splithttp

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

type XmuxConn interface {
	IsClosed() bool
}

type XmuxClient struct {
	XmuxConn XmuxConn

	// Running is the number of logical XHTTP sessions assigned to this client.
	// Together with packetAffinities it drives adaptive expansion: once a packet
	// flow rotates away from its original client, its affinity represents that
	// logical flow's load on the replacement. InFlight only protects transient
	// packet POSTs from being closed while a retired client is draining.
	Running          atomic.Int32
	InFlight         atomic.Int32
	packetAffinities atomic.Int32

	lifecycleMu       sync.Mutex
	targetConcurrency int32
	leftUsage         int32
	LeftRequests      atomic.Int32
	UnreusableAt      time.Time
	// NotUsed is kept for source compatibility. New code should use Retired;
	// both flags are treated as the same admission state.
	NotUsed      atomic.Bool
	Retired      atomic.Bool
	closeStarted atomic.Bool
}

func (c *XmuxClient) isRetired() bool {
	return c.Retired.Load() || c.NotUsed.Load()
}

// beginCloseIfIdleLocked atomically closes admission before the underlying
// transport is closed. Callers must hold lifecycleMu.
func (c *XmuxClient) beginCloseIfIdleLocked() bool {
	return c.isRetired() &&
		c.Running.Load() == 0 &&
		c.InFlight.Load() == 0 &&
		c.packetAffinities.Load() == 0 &&
		c.closeStarted.CompareAndSwap(false, true)
}

func (c *XmuxClient) markRetired() bool {
	c.lifecycleMu.Lock()
	c.Retired.Store(true)
	c.NotUsed.Store(true)
	shouldClose := c.beginCloseIfIdleLocked()
	c.lifecycleMu.Unlock()
	return shouldClose
}

// AddRunning and DoneRunning are retained for callers of the pre-lease API.
// New code should use an XmuxLease so admission and accounting are atomic.
func (c *XmuxClient) AddRunning() {
	c.Running.Add(1)
}

func (c *XmuxClient) DoneRunning() {
	c.release(xmuxSessionLease)
}

func (c *XmuxClient) finishClose() {
	common.Close(c.XmuxConn)
}

func (c *XmuxClient) release(kind xmuxLeaseKind) {
	if c.releaseReference(kind) {
		c.finishClose()
	}
}

func (c *XmuxClient) releaseReference(kind xmuxLeaseKind) bool {
	c.lifecycleMu.Lock()
	switch kind {
	case xmuxSessionLease:
		c.Running.Add(-1)
	case xmuxRequestLease:
		c.InFlight.Add(-1)
	case xmuxPacketAffinityLease:
		c.packetAffinities.Add(-1)
	}
	shouldClose := c.beginCloseIfIdleLocked()
	c.lifecycleMu.Unlock()
	return shouldClose
}

// tryAcquireSession reserves the logical session and all HTTP requests that
// must be opened before Dial can return. The manager lock serializes request
// budgets; lifecycleMu serializes admission against retirement and closing.
func (c *XmuxClient) tryAcquireSession(requestSlots int32) bool {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.isRetired() || c.closeStarted.Load() || c.XmuxConn.IsClosed() {
		return false
	}
	if requestSlots > 0 {
		remaining := c.LeftRequests.Load()
		if remaining < requestSlots {
			return false
		}
		c.LeftRequests.Store(remaining - requestSlots)
	}
	c.Running.Add(1)
	return true
}

// tryAcquireRequest reserves one transient request. A retired preferred client
// is admitted only while its owning logical session is still pinned to it.
func (c *XmuxClient) tryAcquireRequest(now time.Time, preferred, pinAffinity bool) bool {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closeStarted.Load() || c.XmuxConn.IsClosed() {
		return false
	}
	retired := c.isRetired()
	if retired && (!preferred || (c.Running.Load() <= 0 && c.packetAffinities.Load() <= 0)) {
		return false
	}
	if !c.UnreusableAt.IsZero() && now.After(c.UnreusableAt) {
		return false
	}
	remaining := c.LeftRequests.Load()
	if remaining <= 0 {
		return false
	}
	c.LeftRequests.Store(remaining - 1)
	c.InFlight.Add(1)
	if pinAffinity {
		c.packetAffinities.Add(1)
	}
	return true
}

const maxConcurrentAsyncXmuxCloses = 8

// xmuxAsyncCloseSlots bounds manager-detached cleanup goroutines. Lease
// Release and explicit Retire keep their synchronous Close semantics. If every
// slot is occupied by a stuck transport Close, rotations across managers apply
// backpressure after releasing manager locks instead of accumulating internal
// goroutines and transport references.
var xmuxAsyncCloseSlots = make(chan struct{}, maxConcurrentAsyncXmuxCloses)

type xmuxLeaseKind uint8

const (
	xmuxSessionLease xmuxLeaseKind = iota
	xmuxRequestLease
	xmuxPacketAffinityLease
)

// XmuxLease makes session and request reservations explicit and idempotent.
// Selection and reservation happen in one manager critical section.
type XmuxLease struct {
	manager  *XmuxManager
	client   *XmuxClient
	kind     xmuxLeaseKind
	released atomic.Bool
}

func (l *XmuxLease) Client() *XmuxClient {
	if l == nil {
		return nil
	}
	return l.client
}

func (l *XmuxLease) Release() {
	if client := l.releaseClientReference(); client != nil {
		client.finishClose()
	}
}

// releaseClientReference completes accounting without running a possibly
// blocking transport Close. This lets owners with multiple leases return all
// counters first and then choose synchronous or bounded asynchronous cleanup.
func (l *XmuxLease) releaseClientReference() *XmuxClient {
	if l == nil || !l.released.CompareAndSwap(false, true) {
		return nil
	}
	if l.client.releaseReference(l.kind) {
		return l.client
	}
	return nil
}

// releaseAsync is used when an upload flow has already transferred its
// affinity to a replacement. A slow transport Close must not prevent the new
// packet request from starting; the same global bound as manager cleanup keeps
// detached closes from accumulating without limit.
func (l *XmuxLease) releaseAsync() {
	if client := l.releaseClientReference(); client != nil {
		closeXmuxClients([]*XmuxClient{client})
	}
}

// Retire prevents future sessions from using this lease's transport. Existing
// sessions and requests drain before the transport is closed.
func (l *XmuxLease) Retire() {
	if l == nil || l.manager == nil || l.client == nil {
		return
	}
	l.manager.retireClient(l.client)
}

type XmuxManager struct {
	mu sync.Mutex

	xmuxConfig        *XmuxConfig
	targetConcurrency int32
	adaptive          bool
	maxConnections    int32
	newConnFunc       func() XmuxConn
	xmuxClients       []*XmuxClient

	// H1 packet-up long responses share a six-connection Transport with finite
	// packet requests. Five admissions leave one physical connection available so
	// the protocol cannot deadlock with all sockets held by stream-down.
	h1PacketDownSlots chan struct{}
}

type h1PacketDownLease struct {
	slots    chan struct{}
	released atomic.Bool
}

func (l *h1PacketDownLease) Release() {
	if l == nil || !l.released.CompareAndSwap(false, true) {
		return
	}
	<-l.slots
}

func (m *XmuxManager) acquireH1PacketDown(ctx context.Context) (*h1PacketDownLease, error) {
	if m == nil || m.h1PacketDownSlots == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case m.h1PacketDownSlots <- struct{}{}:
		// Cancellation may race with a newly available slot. Prefer cancellation
		// during setup and return the token instead of opening an unwanted stream.
		if err := ctx.Err(); err != nil {
			<-m.h1PacketDownSlots
			return nil, err
		}
		return &h1PacketDownLease{slots: m.h1PacketDownSlots}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *XmuxManager) enableH1PacketDownAdmission() {
	if m != nil && m.h1PacketDownSlots == nil {
		// Native managers call this before publication in globalDialerMap.
		m.h1PacketDownSlots = make(chan struct{}, h1MaxPacketDownConnections)
	}
}

func (m *XmuxManager) hasH1PacketDownAdmission() bool {
	return m != nil && m.h1PacketDownSlots != nil
}

// NewXmuxManager preserves the exact original value-based API. New internal
// code uses NewXmuxManagerForHTTPVersion to avoid copying a protobuf message
// and to resolve auto limits from the preselected HTTP version.
func NewXmuxManager(xmuxConfig XmuxConfig, newConnFunc func() XmuxConn) *XmuxManager {
	// This entry point predates protocol-aware defaults. Use the caller's values
	// directly so nil/zero and half-open ranges retain their original sampled
	// meanings: disabled concurrency, an uncapped zero connection limit, and
	// unlimited omitted hMax limits.
	return newResolvedXmuxManager(&xmuxConfig, newConnFunc)
}

// NewXmuxManagerForHTTPVersion resolves auto limits for the preselected HTTP version.
func NewXmuxManagerForHTTPVersion(xmuxConfig *XmuxConfig, httpVersion string, newConnFunc func() XmuxConn) *XmuxManager {
	return newXmuxManager(xmuxConfig, httpVersion, newConnFunc)
}

func newXmuxManager(xmuxConfig *XmuxConfig, httpVersion string, newConnFunc func() XmuxConn) *XmuxManager {
	resolved := resolveXmuxConfig(xmuxConfig, httpVersion)
	return newResolvedXmuxManager(resolved, newConnFunc)
}

func newResolvedXmuxManager(resolved *XmuxConfig, newConnFunc func() XmuxConn) *XmuxManager {
	targetConcurrency := resolved.GetNormalizedMaxConcurrency().rand()
	manager := &XmuxManager{
		xmuxConfig:        resolved,
		targetConcurrency: targetConcurrency,
		adaptive:          targetConcurrency > 0,
		maxConnections:    resolved.GetNormalizedMaxConnections().rand(),
		newConnFunc:       newConnFunc,
		xmuxClients:       make([]*XmuxClient, 0),
	}
	return manager
}

func (m *XmuxManager) newXmuxClientLocked(minimumRequestSlots int32) *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:          m.newConnFunc(),
		targetConcurrency: m.targetConcurrency,
		leftUsage:         -1,
	}
	if x := m.xmuxConfig.GetNormalizedCMaxReuseTimes().rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	requestSlots := int32(math.MaxInt32)
	if x := m.xmuxConfig.GetNormalizedHMaxRequestTimes().rand(); x > 0 {
		requestSlots = x
	}
	// A single logical session can require two initial HTTP streams. Treat that
	// indivisible setup as the minimum budget for a fresh client, then retire it
	// immediately afterwards if the configured hMax was smaller.
	if requestSlots < minimumRequestSlots {
		requestSlots = minimumRequestSlots
	}
	xmuxClient.LeftRequests.Store(requestSlots)
	if x := m.xmuxConfig.GetNormalizedHMaxReusableSecs().rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	return xmuxClient
}

func (m *XmuxManager) retireUnusableLocked(ctx context.Context, now time.Time, minimumRequestSlots int32) (toClose []*XmuxClient) {
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		isClosed := xmuxClient.XmuxConn.IsClosed()
		if xmuxClient.isRetired() ||
			isClosed ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(minimumRequestSlots > 0 && xmuxClient.LeftRequests.Load() < minimumRequestSlots) ||
			(!xmuxClient.UnreusableAt.IsZero() && now.After(xmuxClient.UnreusableAt)) {
			errors.LogDebug(ctx, "XMUX: retiring xmuxClient, IsClosed() = ", isClosed,
				", Running = ", xmuxClient.Running.Load(),
				", InFlight = ", xmuxClient.InFlight.Load(),
				", packetAffinities = ", xmuxClient.packetAffinities.Load(),
				", leftUsage = ", xmuxClient.leftUsage,
				", LeftRequests = ", xmuxClient.LeftRequests.Load(),
				", UnreusableAt = ", xmuxClient.UnreusableAt)
			if xmuxClient.markRetired() {
				toClose = append(toClose, xmuxClient)
			}
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
			continue
		}
		i++
	}
	return toClose
}

func closeXmuxClients(clients []*XmuxClient) {
	for _, client := range clients {
		// Closing an old H3 transport can wait on its own internal state. Its
		// admission gate is already closed, so do not hold up delivery of a newly
		// reserved lease while capacity is available. The bounded slots prevent a
		// stuck Close from causing unbounded cleanup goroutine growth.
		xmuxAsyncCloseSlots <- struct{}{}
		go func(client *XmuxClient) {
			defer func() { <-xmuxAsyncCloseSlots }()
			client.finishClose()
		}(client)
	}
}

func releaseXmuxLeasesAsync(leases ...*XmuxLease) {
	toClose := make([]*XmuxClient, 0, len(leases))
	// Complete every accounting transition before starting a transport Close;
	// one stuck Close must not leave unrelated session counters reserved.
	for _, lease := range leases {
		if client := lease.releaseClientReference(); client != nil {
			toClose = append(toClose, client)
		}
	}
	closeXmuxClients(toClose)
}

// GetXmuxClient retains the pre-lease selection API for source compatibility.
// New code should use AcquireSessionWithRequests so selection and reservation
// cannot race.
func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient {
	m.mu.Lock()
	client, toClose := m.selectClientLocked(ctx, 0)
	m.mu.Unlock()
	closeXmuxClients(toClose)
	return client
}

func (m *XmuxManager) retireExhaustedLocked(client *XmuxClient, includeUsage bool) (toClose *XmuxClient) {
	if client.LeftRequests.Load() > 0 && (!includeUsage || client.leftUsage != 0) {
		return nil
	}
	m.removeClientLocked(client)
	if client.markRetired() {
		return client
	}
	return nil
}

func (m *XmuxManager) removeClientLocked(client *XmuxClient) {
	for i, active := range m.xmuxClients {
		if active == client {
			m.xmuxClients = append(m.xmuxClients[:i], m.xmuxClients[i+1:]...)
			return
		}
	}
}

func (m *XmuxManager) retireClient(client *XmuxClient) {
	m.mu.Lock()
	m.removeClientLocked(client)
	shouldClose := client.markRetired()
	m.mu.Unlock()
	if shouldClose {
		client.finishClose()
	}
}

func (c *XmuxClient) schedulerLoad() int64 {
	// Use int64 so summing the two valid int32 counters cannot overflow the
	// scheduler's comparison back below the threshold.
	return int64(c.Running.Load()) + int64(c.packetAffinities.Load())
}

func chooseLeastLoaded(clients []*XmuxClient) *XmuxClient {
	minimum := int64(math.MaxInt64)
	ties := make([]*XmuxClient, 0, len(clients))
	for _, client := range clients {
		load := client.schedulerLoad()
		if load < minimum {
			minimum = load
			ties = ties[:0]
			ties = append(ties, client)
		} else if load == minimum {
			ties = append(ties, client)
		}
	}
	if len(ties) == 1 {
		return ties[0]
	}
	i, err := rand.Int(rand.Reader, big.NewInt(int64(len(ties))))
	if err != nil {
		return ties[0]
	}
	return ties[i.Int64()]
}

func (m *XmuxManager) selectClientLocked(ctx context.Context, minimumRequestSlots int32) (*XmuxClient, []*XmuxClient) {
	toClose := m.retireUnusableLocked(ctx, time.Now(), minimumRequestSlots)
	if len(m.xmuxClients) == 0 {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because the active pool is empty")
		return m.newXmuxClientLocked(minimumRequestSlots), toClose
	}

	// A disabled concurrency dimension preserves the explicit legacy
	// maxConnections-only behavior: eagerly fill the active pool, then reuse.
	if !m.adaptive {
		if m.maxConnections > 0 && len(m.xmuxClients) < int(m.maxConnections) {
			errors.LogDebug(ctx, "XMUX: creating xmuxClient for explicit maxConnections-only policy, xmuxClients = ", len(m.xmuxClients))
			return m.newXmuxClientLocked(minimumRequestSlots), toClose
		}
		return m.useExistingLocked(chooseLeastLoaded(m.xmuxClients)), toClose
	}

	underTarget := make([]*XmuxClient, 0, len(m.xmuxClients))
	for _, xmuxClient := range m.xmuxClients {
		if xmuxClient.schedulerLoad() < int64(xmuxClient.targetConcurrency) {
			underTarget = append(underTarget, xmuxClient)
		}
	}
	if len(underTarget) > 0 {
		return m.useExistingLocked(chooseLeastLoaded(underTarget)), toClose
	}

	if m.maxConnections <= 0 || len(m.xmuxClients) < int(m.maxConnections) {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because the concurrency target was reached, xmuxClients = ", len(m.xmuxClients))
		return m.newXmuxClientLocked(minimumRequestSlots), toClose
	}

	// maxConcurrency is a soft expansion threshold. Once maxConnections is
	// reached, keep reusing the least-loaded active client.
	return m.useExistingLocked(chooseLeastLoaded(m.xmuxClients)), toClose
}

func (m *XmuxManager) useExistingLocked(client *XmuxClient) *XmuxClient {
	if client.leftUsage > 0 {
		client.leftUsage--
	}
	return client
}

func (m *XmuxManager) AcquireSession(ctx context.Context) *XmuxLease {
	return m.AcquireSessionWithRequests(ctx, 0)
}

// AcquireSessionWithRequests atomically selects a client, increments its
// logical-session load, and consumes the initial HTTP request budget.
func (m *XmuxManager) AcquireSessionWithRequests(ctx context.Context, requestSlots int32) *XmuxLease {
	if requestSlots < 0 {
		requestSlots = 0
	}
	if ctx.Err() != nil {
		return nil
	}
	var toClose []*XmuxClient
	m.mu.Lock()
	for {
		if ctx.Err() != nil {
			m.mu.Unlock()
			closeXmuxClients(toClose)
			return nil
		}
		client, retired := m.selectClientLocked(ctx, requestSlots)
		toClose = append(toClose, retired...)
		if client.tryAcquireSession(requestSlots) {
			if retired := m.retireExhaustedLocked(client, true); retired != nil {
				toClose = append(toClose, retired)
			}
			m.mu.Unlock()
			closeXmuxClients(toClose)
			return &XmuxLease{manager: m, client: client, kind: xmuxSessionLease}
		}
		m.removeClientLocked(client)
		if client.markRetired() {
			toClose = append(toClose, client)
		}
	}
}

// BorrowPacket reserves one transient HTTP request. A preferred client remains
// usable by its existing session after it has retired due to cMaxReuseTimes,
// but request-count, lifetime, and connection-health limits still rotate it.
func (m *XmuxManager) BorrowPacket(ctx context.Context, preferred *XmuxClient) *XmuxLease {
	request, _ := m.borrowPacket(ctx, preferred, false)
	return request
}

// borrowPacketWithAffinity also pins a fallback client to the current logical
// upload flow. The caller owns the returned affinity until that flow rotates
// again or closes. Preferred requests need no new pin because the caller
// already owns either the original session lease or a prior affinity lease.
func (m *XmuxManager) borrowPacketWithAffinity(ctx context.Context, preferred *XmuxClient) (*XmuxLease, *XmuxLease) {
	return m.borrowPacket(ctx, preferred, true)
}

func (m *XmuxManager) borrowPacket(ctx context.Context, preferred *XmuxClient, pinFallback bool) (*XmuxLease, *XmuxLease) {
	if ctx.Err() != nil {
		return nil, nil
	}
	var toClose []*XmuxClient
	m.mu.Lock()
	if ctx.Err() != nil {
		m.mu.Unlock()
		return nil, nil
	}
	now := time.Now()
	if preferred != nil && preferred.tryAcquireRequest(now, true, false) {
		if retired := m.retireExhaustedLocked(preferred, false); retired != nil {
			toClose = append(toClose, retired)
		}
		m.mu.Unlock()
		closeXmuxClients(toClose)
		return &XmuxLease{manager: m, client: preferred, kind: xmuxRequestLease}, nil
	}
	for {
		if ctx.Err() != nil {
			m.mu.Unlock()
			closeXmuxClients(toClose)
			return nil, nil
		}
		client, retired := m.selectClientLocked(ctx, 1)
		toClose = append(toClose, retired...)
		if client.tryAcquireRequest(now, false, pinFallback) {
			if exhausted := m.retireExhaustedLocked(client, true); exhausted != nil {
				toClose = append(toClose, exhausted)
			}
			m.mu.Unlock()
			closeXmuxClients(toClose)
			request := &XmuxLease{manager: m, client: client, kind: xmuxRequestLease}
			if pinFallback {
				return request, &XmuxLease{manager: m, client: client, kind: xmuxPacketAffinityLease}
			}
			return request, nil
		}
		m.removeClientLocked(client)
		if client.markRetired() {
			toClose = append(toClose, client)
		}
	}
}
