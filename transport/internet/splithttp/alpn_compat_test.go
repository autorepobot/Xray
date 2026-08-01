package splithttp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type noALPNTLSDecoy struct {
	listener   stdnet.Listener
	conns      sync.Map
	wg         sync.WaitGroup
	acceptDone chan struct{}
	closeOnce  sync.Once
}

func startNoALPNTLSDecoy(t *testing.T) *noALPNTLSDecoy {
	t.Helper()
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	keyPair, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	decoy := &noALPNTLSDecoy{
		listener: stdtls.NewListener(raw, &stdtls.Config{
			Certificates: []stdtls.Certificate{keyPair},
			// REALITY intentionally mirrors a target without negotiating an
			// application protocol. The inner XHTTP H2 preface remains valid.
			NextProtos: nil,
		}),
		acceptDone: make(chan struct{}),
	}
	decoy.wg.Add(1)
	go func() {
		defer decoy.wg.Done()
		defer close(decoy.acceptDone)
		for {
			conn, err := decoy.listener.Accept()
			if err != nil {
				return
			}
			decoy.conns.Store(conn, struct{}{})
			decoy.wg.Add(1)
			go func() {
				defer decoy.wg.Done()
				defer decoy.conns.Delete(conn)
				defer conn.Close()
				tlsConn := conn.(*stdtls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				request := make([]byte, 4096)
				if _, err := tlsConn.Read(request); err == nil {
					_, _ = io.WriteString(tlsConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
				}
			}()
		}
	}()
	t.Cleanup(decoy.Close)
	return decoy
}

func (d *noALPNTLSDecoy) Addr() string {
	return d.listener.Addr().String()
}

func (d *noALPNTLSDecoy) Close() {
	d.closeOnce.Do(func() {
		_ = d.listener.Close()
		// Wait until Accept can no longer publish another connection before
		// closing the tracked set; otherwise Close and Store can race and leave
		// the test blocked in wg.Wait.
		<-d.acceptDone
		d.conns.Range(func(key, _ any) bool {
			conn := key.(stdnet.Conn)
			if tlsConn, ok := conn.(*stdtls.Conn); ok {
				_ = tlsConn.NetConn().Close()
			} else {
				_ = conn.Close()
			}
			return true
		})
		d.wg.Wait()
	})
}

func isolateGlobalDialerManagers(t *testing.T) {
	t.Helper()
	globalDialerAccess.Lock()
	oldMap := globalDialerMap
	globalDialerMap = nil
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		testMap := globalDialerMap
		globalDialerMap = oldMap
		globalDialerAccess.Unlock()

		seen := make(map[*XmuxManager]struct{})
		for _, manager := range testMap {
			if manager == nil {
				continue
			}
			if _, ok := seen[manager]; ok {
				continue
			}
			seen[manager] = struct{}{}
			manager.mu.Lock()
			clients := append([]*XmuxClient(nil), manager.xmuxClients...)
			manager.xmuxClients = nil
			manager.mu.Unlock()
			for _, client := range clients {
				client.finishClose()
			}
		}
	})
}

func primeRealityPostHandshakeCache(t *testing.T, config *goreality.Config) {
	t.Helper()
	if len(config.NextProtos) != 0 {
		t.Fatalf("REALITY server NextProtos = %v, want no negotiated ALPN", config.NextProtos)
	}
	type previousValue struct {
		key    string
		value  any
		loaded bool
	}
	previous := make([]previousValue, 0, len(config.ServerNames)*3)
	for serverName := range config.ServerNames {
		for alpn := range 3 {
			key := fmt.Sprintf("%s %s %d", config.Dest, serverName, alpn)
			value, loaded := goreality.GlobalPostHandshakeRecordsLens.Load(key)
			previous = append(previous, previousValue{key: key, value: value, loaded: loaded})
			goreality.GlobalPostHandshakeRecordsLens.Store(key, []int{})
		}
	}
	t.Cleanup(func() {
		for _, item := range previous {
			if item.loaded {
				goreality.GlobalPostHandshakeRecordsLens.Store(item.key, item.value)
			} else {
				goreality.GlobalPostHandshakeRecordsLens.Delete(item.key)
			}
		}
	})
}

func boundedTestXHTTPConfig(path string) *Config {
	return &Config{
		Path: path,
		Mode: "packet-up",
		Xmux: &XmuxConfig{
			MaxConcurrency:   &RangeConfig{From: 32, To: 32},
			MaxConnections:   &RangeConfig{From: 1, To: 1},
			HMaxRequestTimes: &RangeConfig{From: 8, To: 8},
		},
	}
}

func exerciseXHTTPPacketUp(t *testing.T, serverSettings, clientSettings *internet.MemoryStreamConfig) {
	t.Helper()
	listenPort := tcp.PickPort()
	serverResult := make(chan error, 1)
	listener, err := ListenXH(context.Background(), xnet.LocalHostIP, listenPort, serverSettings, func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			want := []byte("request over packet-up")
			got := make([]byte, len(want))
			if _, err := io.ReadFull(conn, got); err != nil {
				serverResult <- err
				return
			}
			if !bytes.Equal(got, want) {
				serverResult <- fmt.Errorf("server received %q, want %q", got, want)
				return
			}
			_, err := conn.Write([]byte("response over stream-down"))
			serverResult <- err
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := Dial(ctx, xnet.TCPDestination(xnet.DomainAddress("localhost"), listenPort), clientSettings)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("request over packet-up")); err != nil {
		t.Fatal(err)
	}
	want := []byte("response over stream-down")
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("client received %q, want %q", got, want)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	waitForPacketRequests(t)
}

func waitForPacketRequests(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		globalDialerAccess.Lock()
		managers := make([]*XmuxManager, 0, len(globalDialerMap))
		for _, manager := range globalDialerMap {
			managers = append(managers, manager)
		}
		globalDialerAccess.Unlock()
		inFlight := false
		for _, manager := range managers {
			manager.mu.Lock()
			clients := append([]*XmuxClient(nil), manager.xmuxClients...)
			manager.mu.Unlock()
			for _, client := range clients {
				if client.InFlight.Load() != 0 {
					inFlight = true
					break
				}
			}
		}
		if !inFlight {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("packet-up acknowledgement did not complete")
		}
	}
}

func TestXHTTPRealityPacketUpDoesNotRequireALPN(t *testing.T) {
	decoy := startNoALPNTLSDecoy(t)
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	serverReality := &reality.Config{
		Dest:        decoy.Addr(),
		ServerNames: []string{"localhost"},
		PrivateKey:  privateKey.Bytes(),
		ShortIds:    [][]byte{shortID},
		Type:        "tcp",
	}
	primeRealityPostHandshakeCache(t, serverReality.GetREALITYConfig())
	isolateGlobalDialerManagers(t)
	serverSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: boundedTestXHTTPConfig("/reality-alpn"),
		SecurityType:     "reality",
		SecuritySettings: serverReality,
	}
	clientSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: boundedTestXHTTPConfig("/reality-alpn"),
		SecurityType:     "reality",
		SecuritySettings: &reality.Config{
			Fingerprint: "chrome",
			ServerName:  "localhost",
			PublicKey:   privateKey.PublicKey().Bytes(),
			ShortId:     shortID,
			SpiderX:     "/",
		},
	}

	exerciseXHTTPPacketUp(t, serverSettings, clientSettings)
}
