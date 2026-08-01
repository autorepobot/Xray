package splithttp

import (
	"context"
	stderrors "errors"
	stdnet "net"
	"sync"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func reserveUDPPort(t *testing.T) net.Port {
	t.Helper()
	conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := net.Port(conn.LocalAddr().(*stdnet.UDPAddr).Port)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestListenQUICEarlyOwnedClosesPacketConnOnFailure(t *testing.T) {
	conn, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()

	if _, err := listenQUICEarlyOwned(conn, nil, &quic.Config{}); err == nil {
		t.Fatal("QUIC listener with a nil TLS config unexpectedly succeeded")
	}
	rebound, err := stdnet.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("failed QUIC construction retained its UDP socket: %v", err)
	}
	rebound.Close()
}

func TestH3ListenHonorsCanceledContext(t *testing.T) {
	port := reserveUDPPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{NextProtocol: []string{"h3"}},
	}
	listener, err := ListenXH(ctx, net.LocalHostIP, port, settings, nil)
	if listener != nil {
		listener.Close()
	}
	if !stderrors.Is(err, context.Canceled) {
		t.Fatalf("ListenXH() error = %v, want context canceled", err)
	}
}

func TestH3ListenerCloseReleasesPacketConnAndIsIdempotent(t *testing.T) {
	port := reserveUDPPort(t)
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			ServerMaxHeaderBytes: 4096,
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			Certificate:  []*tls.Certificate{tls.ParseCertificate(ct)},
			NextProtocol: []string{"h3"},
		},
	}

	raw, err := ListenXH(context.Background(), net.LocalHostIP, port, settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := raw.(*Listener)
	if listener.h3server == nil || listener.h3listener == nil || listener.h3PacketConn == nil {
		t.Fatal("H3 listener did not retain all owned transport layers")
	}
	if got := listener.h3server.MaxHeaderBytes; got != 4096 {
		t.Fatalf("HTTP/3 MaxHeaderBytes = %d, want 4096", got)
	}
	addr := listener.Addr().String()

	const closers = 8
	start := make(chan struct{})
	errs := make(chan error, closers)
	var wg sync.WaitGroup
	for range closers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- listener.Close()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Listener.Close() = %v", err)
		}
	}

	rebound, err := stdnet.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("closed H3 listener retained its UDP socket: %v", err)
	}
	rebound.Close()
}

func TestH3ListenerPreservesHTTP3DefaultHeaderLimit(t *testing.T) {
	port := reserveUDPPort(t)
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate:  []*tls.Certificate{tls.ParseCertificate(ct)},
			NextProtocol: []string{"h3"},
		},
	}
	raw, err := ListenXH(context.Background(), net.LocalHostIP, port, settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := raw.(*Listener)
	defer listener.Close()
	if got := listener.h3server.MaxHeaderBytes; got != 0 {
		t.Fatalf("HTTP/3 default MaxHeaderBytes = %d, want zero-value library default", got)
	}
}
