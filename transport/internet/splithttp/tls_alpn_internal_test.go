package splithttp

import (
	"context"
	stdtls "crypto/tls"
	stdnet "net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestUTLSExplicitH1OverridesBrowserPresetALPN(t *testing.T) {
	ct, _ := cert.MustGenerate(nil, cert.CommonName("localhost"))
	certPEM, keyPEM := ct.ToPEM()
	keyPair, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &stdtls.Config{
		Certificates: []stdtls.Certificate{keyPair},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	type handshakeResult struct {
		alpn string
		err  error
	}
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan handshakeResult, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- handshakeResult{err: err}
			return
		}
		defer raw.Close()
		server := stdtls.Server(raw, serverConfig)
		err = server.Handshake()
		serverDone <- handshakeResult{alpn: server.ConnectionState().NegotiatedProtocol, err: err}
	}()

	clientRaw, err := stdnet.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	clientConfig := &stdtls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{"http/1.1"},
	}
	wrapped := xtls.UClient(clientRaw, clientConfig, xtls.GetFingerprint(""))
	client := wrapped.(*xtls.UConn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := handshakeUTLSForHTTP(ctx, client, clientConfig, "1.1"); err != nil {
		t.Fatal(err)
	}
	if got := client.NegotiatedProtocol(); got != "http/1.1" {
		t.Fatalf("client ALPN = %q, want http/1.1", got)
	}
	select {
	case result := <-serverDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.alpn != "http/1.1" {
			t.Fatalf("server ALPN = %q, want http/1.1", result.alpn)
		}
	case <-ctx.Done():
		t.Fatal("server TLS handshake did not complete")
	}
}

func TestUTLSH1PreservesNoALPNFingerprint(t *testing.T) {
	clientRaw, peer := stdnet.Pipe()
	defer clientRaw.Close()
	defer peer.Close()
	clientConfig := &stdtls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{"http/1.1"},
	}
	wrapped := xtls.UClient(clientRaw, clientConfig, xtls.GetFingerprint("randomizednoalpn"))
	client := wrapped.(*xtls.UConn)
	if err := prepareUTLSForHTTP(client, clientConfig, "1.1"); err != nil {
		t.Fatal(err)
	}
	for _, extension := range client.Extensions {
		if _, ok := extension.(*utls.ALPNExtension); ok {
			t.Fatal("H1 preparation added ALPN to a no-ALPN fingerprint")
		}
	}
}
