package splithttp

import (
	"context"
	"testing"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestValidateH3Congestion(t *testing.T) {
	tests := []struct {
		name   string
		params *internet.QuicParams
		valid  bool
	}{
		{name: "defaults", params: &internet.QuicParams{}, valid: true},
		{name: "bbr", params: &internet.QuicParams{Congestion: "bbr", BbrProfile: "aggressive"}, valid: true},
		{name: "reno", params: &internet.QuicParams{Congestion: "reno"}, valid: true},
		{name: "force brutal", params: &internet.QuicParams{Congestion: "force-brutal", BrutalUp: minH3BrutalRate}, valid: true},
		{name: "case insensitive direct API", params: &internet.QuicParams{Congestion: "BBR", BbrProfile: "STANDARD"}, valid: true},
		{name: "ordinary brutal lacks negotiation", params: &internet.QuicParams{Congestion: "brutal", BrutalUp: minH3BrutalRate}},
		{name: "force brutal without rate", params: &internet.QuicParams{Congestion: "force-brutal"}},
		{name: "force brutal below minimum", params: &internet.QuicParams{Congestion: "force-brutal", BrutalUp: minH3BrutalRate - 1}},
		{name: "invalid bbr profile", params: &internet.QuicParams{Congestion: "bbr", BbrProfile: "fastest"}},
		{name: "unknown", params: &internet.QuicParams{Congestion: "cubic"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateH3Congestion(test.params)
			if (err == nil) != test.valid {
				t.Fatalf("validateH3Congestion(%+v) error = %v, valid = %v", test.params, err, test.valid)
			}
		})
	}
}

func TestH3ClientAndServerRejectUnsupportedCongestionWithoutPanic(t *testing.T) {
	newSettings := func() *internet.MemoryStreamConfig {
		return &internet.MemoryStreamConfig{
			ProtocolName:     protocolName,
			ProtocolSettings: &Config{},
			SecurityType:     "tls",
			SecuritySettings: &xtls.Config{ServerName: "localhost", NextProtocol: []string{"h3"}},
			QuicParams:       &internet.QuicParams{Congestion: "brutal", BrutalUp: minH3BrutalRate},
		}
	}

	client := createHTTPClient(net.TCPDestination(net.LocalHostIP, 443), newSettings()).(*DefaultDialerClient)
	transport := client.client.Transport.(*http3.Transport)
	if _, err := transport.Dial(context.Background(), "", nil, nil); err == nil {
		t.Fatal("H3 client accepted unsupported ordinary brutal")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	if listener, err := ListenXH(context.Background(), net.LocalHostIP, 443, newSettings(), nil); err == nil {
		listener.Close()
		t.Fatal("H3 server accepted unsupported ordinary brutal")
	}
}
