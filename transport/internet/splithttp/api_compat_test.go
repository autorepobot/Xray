package splithttp_test

import (
	"context"
	"io"
	"math"
	stdnet "net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

type legacyDialerClient struct {
	closed     atomic.Bool
	closeCount atomic.Int32
}

func (c *legacyDialerClient) IsClosed() bool { return c.closed.Load() }
func (*legacyDialerClient) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, xnet.Addr, xnet.Addr, error) {
	return io.NopCloser(strings.NewReader("")), &xnet.IPAddr{}, &xnet.IPAddr{}, nil
}

func (*legacyDialerClient) PostPacket(context.Context, string, string, string, buf.MultiBuffer) error {
	return nil
}

func (c *legacyDialerClient) Close() error {
	c.closeCount.Add(1)
	c.closed.Store(true)
	return nil
}

var (
	_ splithttp.DialerClient                                                       = (*legacyDialerClient)(nil)
	_ func(splithttp.XmuxConfig, func() splithttp.XmuxConn) *splithttp.XmuxManager = splithttp.NewXmuxManager
)

func TestLegacyExportedAPIStillWorks(t *testing.T) {
	transport := &legacyDialerClient{}
	manager := splithttp.NewXmuxManager(splithttp.XmuxConfig{
		MaxConcurrency: &splithttp.RangeConfig{From: -1, To: -1},
		MaxConnections: &splithttp.RangeConfig{From: 1, To: 1},
	}, func() splithttp.XmuxConn { return transport })
	client := manager.GetXmuxClient(context.Background())
	if client == nil {
		t.Fatal("legacy GetXmuxClient returned nil")
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if manager.GetXmuxClient(canceledCtx) == nil {
		t.Fatal("legacy GetXmuxClient changed behavior for an already-canceled context")
	}
	client.AddRunning()
	client.NotUsed.Store(true)
	client.DoneRunning()
	if transport.closeCount.Load() != 1 {
		t.Fatalf("legacy DoneRunning closed transport %d times, want 1", transport.closeCount.Load())
	}

	wait := make(chan struct{})
	reader := &splithttp.WaitReadCloser{
		Wait:       wait,
		ReadCloser: io.NopCloser(strings.NewReader("x")),
	}
	buffer := make([]byte, 1)
	if n, err := reader.Read(buffer); err != nil || n != 1 || string(buffer) != "x" {
		t.Fatalf("legacy WaitReadCloser read = %q, %d, %v", buffer, n, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}

	left, right := stdnet.Pipe()
	h1 := splithttp.NewH1Conn(left)
	if h1.Conn != left || h1.RespBufReader == nil {
		t.Fatal("legacy H1Conn wrapper was not initialized")
	}
	h1.Close()
	right.Close()
}

func TestLegacyXmuxValuesKeepOriginalPolicy(t *testing.T) {
	tests := []struct {
		name        string
		newManager  func(func() splithttp.XmuxConn) *splithttp.XmuxManager
		sessions    int
		wantCreated int
	}{
		{
			name: "omitted limits keep one unlimited client",
			newManager: func(newConn func() splithttp.XmuxConn) *splithttp.XmuxManager {
				return splithttp.NewXmuxManager(splithttp.XmuxConfig{}, newConn)
			},
			sessions:    128,
			wantCreated: 1,
		},
		{
			name: "explicit zero limits keep one unlimited client",
			newManager: func(newConn func() splithttp.XmuxConn) *splithttp.XmuxManager {
				return splithttp.NewXmuxManager(splithttp.XmuxConfig{
					MaxConcurrency: &splithttp.RangeConfig{},
					MaxConnections: &splithttp.RangeConfig{},
				}, newConn)
			},
			sessions:    128,
			wantCreated: 1,
		},
		{
			name: "half-open nonpositive ranges retain legacy sampling",
			newManager: func(newConn func() splithttp.XmuxConn) *splithttp.XmuxManager {
				return splithttp.NewXmuxManager(splithttp.XmuxConfig{
					MaxConcurrency:   &splithttp.RangeConfig{From: -1, To: 1},
					MaxConnections:   &splithttp.RangeConfig{From: 0, To: 1},
					HMaxRequestTimes: &splithttp.RangeConfig{From: 0, To: 1},
					HMaxReusableSecs: &splithttp.RangeConfig{From: 0, To: 1},
				}, newConn)
			},
			sessions:    128,
			wantCreated: 1,
		},
		{
			name: "zero concurrency retains eager explicit connection count",
			newManager: func(newConn func() splithttp.XmuxConn) *splithttp.XmuxManager {
				return splithttp.NewXmuxManager(splithttp.XmuxConfig{
					MaxConnections: &splithttp.RangeConfig{From: 3, To: 3},
				}, newConn)
			},
			sessions:    3,
			wantCreated: 3,
		},
		{
			name: "zero connections retains uncapped adaptive expansion",
			newManager: func(newConn func() splithttp.XmuxConn) *splithttp.XmuxManager {
				return splithttp.NewXmuxManager(splithttp.XmuxConfig{
					MaxConcurrency: &splithttp.RangeConfig{From: 1, To: 1},
					MaxConnections: &splithttp.RangeConfig{},
				}, newConn)
			},
			sessions:    4,
			wantCreated: 4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var created []*legacyDialerClient
			manager := test.newManager(func() splithttp.XmuxConn {
				transport := &legacyDialerClient{}
				created = append(created, transport)
				return transport
			})

			acquired := make([]*splithttp.XmuxClient, 0, test.sessions)
			unique := make(map[*splithttp.XmuxClient]struct{})
			for range test.sessions {
				client := manager.GetXmuxClient(context.Background())
				if client.LeftRequests.Load() != math.MaxInt32 {
					t.Fatalf("legacy omitted hMaxRequestTimes left %d requests, want unlimited", client.LeftRequests.Load())
				}
				if !client.UnreusableAt.IsZero() {
					t.Fatalf("legacy omitted hMaxReusableSecs set deadline %v, want unlimited", client.UnreusableAt)
				}
				client.AddRunning()
				acquired = append(acquired, client)
				unique[client] = struct{}{}
			}

			if len(created) != test.wantCreated {
				t.Fatalf("legacy zero-value policy created %d clients, want %d", len(created), test.wantCreated)
			}
			for client := range unique {
				client.NotUsed.Store(true)
			}
			for _, client := range acquired {
				client.DoneRunning()
			}
			for i, transport := range created {
				if got := transport.closeCount.Load(); got != 1 {
					t.Fatalf("legacy transport %d closed %d times, want 1", i, got)
				}
			}
		})
	}
}
