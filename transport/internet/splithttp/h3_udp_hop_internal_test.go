package splithttp

import (
	"context"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

type closeCountingPacketConn struct {
	closes atomic.Int32
}

func (*closeCountingPacketConn) ReadFrom([]byte) (int, stdnet.Addr, error) {
	return 0, nil, stdnet.ErrClosed
}

func (*closeCountingPacketConn) WriteTo([]byte, stdnet.Addr) (int, error) {
	return 0, stdnet.ErrClosed
}

func (c *closeCountingPacketConn) Close() error {
	c.closes.Add(1)
	return nil
}

func (*closeCountingPacketConn) LocalAddr() stdnet.Addr           { return &stdnet.UDPAddr{} }
func (*closeCountingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*closeCountingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*closeCountingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestH3UDPHopOutlivesTransportDialContext(t *testing.T) {
	setupCtx, cancelSetup := context.WithCancel(context.Background())
	lifetime := newH3PacketConnLifetime(setupCtx)
	packetConn := &closeCountingPacketConn{}
	var observedHopCtx context.Context

	hopDialer := lifetime.udpHopDialer(nil, func(ctx context.Context, dest net.Destination, _ *internet.SocketConfig) (net.Conn, error) {
		observedHopCtx = ctx
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &internet.PacketConnWrapper{
			PacketConn: packetConn,
			Dest:       &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: int(dest.Port)},
		}, nil
	})

	// http3.Transport cancels its Dial context immediately after the callback
	// returns. A later UDP hop must not inherit that cancellation.
	cancelSetup()
	hopped, err := hopDialer(&stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 443})
	if err != nil {
		t.Fatalf("UDP hop inherited the completed Dial context: %v", err)
	}
	if hopped != packetConn {
		t.Fatalf("hop dialer returned %T, want the dialed PacketConn", hopped)
	}
	if observedHopCtx == nil || observedHopCtx.Err() != nil {
		t.Fatalf("hop context after setup cancellation = %v, want live context", observedHopCtx)
	}

	lifetime.setPacketConn(hopped)
	connCtx, cancelConn := context.WithCancel(context.Background())
	lifetime.closeWhenDone(connCtx)
	cancelConn()

	deadline := time.Now().Add(time.Second)
	for packetConn.closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := packetConn.closes.Load(); got != 1 {
		t.Fatalf("PacketConn close count = %d, want 1", got)
	}
	if err := observedHopCtx.Err(); err != context.Canceled {
		t.Fatalf("hop context after QUIC close = %v, want context.Canceled", err)
	}

	// Error paths and connection completion may race; cleanup remains idempotent.
	lifetime.close()
	if got := packetConn.closes.Load(); got != 1 {
		t.Fatalf("PacketConn close count after repeated cleanup = %d, want 1", got)
	}
}

func TestCreateH3ClientAcceptsNilUDPHop(t *testing.T) {
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &xtls.Config{
			ServerName:   "localhost",
			NextProtocol: []string{"h3"},
		},
		QuicParams: &internet.QuicParams{},
	}

	client := createHTTPClient(net.TCPDestination(net.LocalHostIP, 443), settings).(*DefaultDialerClient)
	if client.httpVersion != "3" {
		t.Fatalf("httpVersion = %q, want 3", client.httpVersion)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestH3AcceptsDirectUDPConnFromAlternativeSystemDialer(t *testing.T) {
	listener, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := stdnet.DialUDP("udp", nil, listener.LocalAddr().(*stdnet.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	packetConn, err := h3PacketConnFromSystemConn(conn)
	if err != nil {
		t.Fatalf("direct *net.UDPConn was rejected: %v", err)
	}
	if _, ok := packetConn.(*h3ConnectedPacketConn); !ok {
		t.Fatalf("converted PacketConn = %T, want connected UDP adapter", packetConn)
	}
	remoteAddr, err := h3RemoteUDPAddr(conn)
	if err != nil {
		t.Fatal(err)
	}
	if remoteAddr.Port != listener.LocalAddr().(*stdnet.UDPAddr).Port {
		t.Fatalf("remote UDP port = %d, want %d", remoteAddr.Port, listener.LocalAddr().(*stdnet.UDPAddr).Port)
	}

	payload := []byte("packet")
	if _, err := packetConn.WriteTo(payload, remoteAddr); err != nil {
		t.Fatalf("connected PacketConn.WriteTo failed: %v", err)
	}
	buffer := make([]byte, len(payload))
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, sourceAddr, err := listener.ReadFrom(buffer)
	if err != nil || n != len(payload) || string(buffer) != string(payload) {
		t.Fatalf("listener ReadFrom = %q, %d, %v; want %q", buffer, n, err, payload)
	}
	reply := []byte("reply")
	if _, err := listener.WriteTo(reply, sourceAddr); err != nil {
		t.Fatal(err)
	}
	if err := packetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer = make([]byte, len(reply))
	if n, addr, err := packetConn.ReadFrom(buffer); err != nil || n != len(reply) || string(buffer) != string(reply) || addr.String() != remoteAddr.String() {
		t.Fatalf("connected PacketConn.ReadFrom = %q, %d, %v, %v; want %q from %v", buffer, n, addr, err, reply, remoteAddr)
	}
}

func TestH3DialRejectsInvalidUDPHopBeforeNetwork(t *testing.T) {
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &xtls.Config{ServerName: "localhost", NextProtocol: []string{"h3"}},
		QuicParams: &internet.QuicParams{
			UdpHop: &internet.UdpHop{Ports: []uint32{443}, IntervalMax: 10},
		},
	}
	client := createHTTPClient(net.TCPDestination(net.LocalHostIP, 443), settings).(*DefaultDialerClient)
	defer client.Close()

	transport := client.client.Transport.(*http3.Transport)
	if _, err := transport.Dial(context.Background(), "", nil, nil); err == nil {
		t.Fatal("invalid effective UDP hop interval unexpectedly reached network setup")
	}
}
