package splithttp

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func assertRange(t *testing.T, name string, got *RangeConfig, from, to int32) {
	t.Helper()
	if got == nil || got.From != from || got.To != to {
		t.Fatalf("%s = %#v, want %d-%d", name, got, from, to)
	}
}

func TestResolveXmuxProtocolDefaults(t *testing.T) {
	tests := []struct {
		version                        string
		concurrencyFrom, concurrencyTo int32
		connections                    int32
	}{
		{version: "1.1", concurrencyFrom: -1, concurrencyTo: -1, connections: 1},
		{version: "http/1.1", concurrencyFrom: -1, concurrencyTo: -1, connections: 1},
		{version: "2", concurrencyFrom: 32, concurrencyTo: 64, connections: 3},
		{version: "3", concurrencyFrom: 64, concurrencyTo: 96, connections: 2},
		{version: "h3", concurrencyFrom: 64, concurrencyTo: 96, connections: 2},
		{version: "unknown", concurrencyFrom: 32, concurrencyTo: 64, connections: 3},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			resolved := resolveXmuxConfig(nil, test.version)
			assertRange(t, "maxConcurrency", resolved.MaxConcurrency, test.concurrencyFrom, test.concurrencyTo)
			assertRange(t, "maxConnections", resolved.MaxConnections, test.connections, test.connections)
			assertRange(t, "hMaxRequestTimes", resolved.HMaxRequestTimes, 600, 900)
			assertRange(t, "hMaxReusableSecs", resolved.HMaxReusableSecs, 1800, 3000)
		})
	}
}

func TestResolveXmuxPartialAutoAndOff(t *testing.T) {
	tests := []struct {
		name                           string
		input                          *XmuxConfig
		version                        string
		concurrencyFrom, concurrencyTo int32
		connections                    int32
	}{
		{
			name:    "explicit concurrency with auto connections",
			input:   &XmuxConfig{MaxConcurrency: &RangeConfig{From: 7, To: 7}},
			version: "2", concurrencyFrom: 7, concurrencyTo: 7, connections: 3,
		},
		{
			name:    "auto concurrency with explicit connections",
			input:   &XmuxConfig{MaxConnections: &RangeConfig{From: 4, To: 4}},
			version: "3", concurrencyFrom: 64, concurrencyTo: 96, connections: 4,
		},
		{
			name: "off is never overwritten",
			input: &XmuxConfig{
				MaxConcurrency: &RangeConfig{From: -1, To: -1},
				MaxConnections: &RangeConfig{From: -1, To: -1},
			},
			version: "2", concurrencyFrom: -1, concurrencyTo: -1, connections: -1,
		},
		{
			name: "legacy negative aliases normalize to off",
			input: &XmuxConfig{
				MaxConcurrency: &RangeConfig{From: -4, To: -2},
				MaxConnections: &RangeConfig{From: -3, To: -3},
			},
			version: "2", concurrencyFrom: -1, concurrencyTo: -1, connections: -1,
		},
		{
			name: "half-open sentinel ranges retain one meaning",
			input: &XmuxConfig{
				MaxConcurrency: &RangeConfig{From: -3, To: 0},
				MaxConnections: &RangeConfig{From: 0, To: 1},
			},
			version: "2", concurrencyFrom: -1, concurrencyTo: -1, connections: 3,
		},
		{
			name: "off concurrency with auto connections",
			input: &XmuxConfig{
				MaxConcurrency: &RangeConfig{From: -1, To: -1},
				MaxConnections: &RangeConfig{},
			},
			version: "2", concurrencyFrom: -1, concurrencyTo: -1, connections: 3,
		},
		{
			name: "auto concurrency with off connections",
			input: &XmuxConfig{
				MaxConcurrency: &RangeConfig{},
				MaxConnections: &RangeConfig{From: -1, To: -1},
			},
			version: "3", concurrencyFrom: 64, concurrencyTo: 96, connections: -1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := resolveXmuxConfig(test.input, test.version)
			assertRange(t, "maxConcurrency", resolved.MaxConcurrency, test.concurrencyFrom, test.concurrencyTo)
			assertRange(t, "maxConnections", resolved.MaxConnections, test.connections, test.connections)
		})
	}
}

func TestResolveXmuxDoesNotMutateInput(t *testing.T) {
	raw := XmuxConfig{
		MaxConcurrency: &RangeConfig{},
		MaxConnections: &RangeConfig{},
	}
	h2 := resolveXmuxConfig(&raw, "2")
	h3 := resolveXmuxConfig(&raw, "3")
	assertRange(t, "raw maxConcurrency", raw.MaxConcurrency, 0, 0)
	assertRange(t, "raw maxConnections", raw.MaxConnections, 0, 0)
	if raw.HMaxRequestTimes != nil || raw.HMaxReusableSecs != nil {
		t.Fatal("resolveXmuxConfig mutated omitted hMax fields")
	}
	assertRange(t, "H2 maxConcurrency", h2.MaxConcurrency, 32, 64)
	assertRange(t, "H3 maxConcurrency", h3.MaxConcurrency, 64, 96)
	assertRange(t, "H2 hMaxRequestTimes", h2.HMaxRequestTimes, 600, 900)
	assertRange(t, "H3 hMaxReusableSecs", h3.HMaxReusableSecs, 1800, 3000)
}

func TestResolveXmuxHMaxDefaultsAreIndependent(t *testing.T) {
	configured := resolveXmuxConfig(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 1, To: 1},
	}, "2")
	assertRange(t, "configured hMaxRequestTimes", configured.HMaxRequestTimes, 600, 900)
	assertRange(t, "configured hMaxReusableSecs", configured.HMaxReusableSecs, 1800, 3000)

	keepAliveOnly := resolveXmuxConfig(&XmuxConfig{HKeepAlivePeriod: -1}, "2")
	assertRange(t, "keepalive hMaxRequestTimes", keepAliveOnly.HMaxRequestTimes, 600, 900)
	assertRange(t, "keepalive hMaxReusableSecs", keepAliveOnly.HMaxReusableSecs, 1800, 3000)

	cMaxOnly := resolveXmuxConfig(&XmuxConfig{CMaxReuseTimes: &RangeConfig{From: 2, To: 2}}, "2")
	assertRange(t, "cMax hMaxRequestTimes", cMaxOnly.HMaxRequestTimes, 600, 900)
	assertRange(t, "cMax hMaxReusableSecs", cMaxOnly.HMaxReusableSecs, 1800, 3000)

	requestOnly := resolveXmuxConfig(&XmuxConfig{HMaxRequestTimes: &RangeConfig{From: 10, To: 20}}, "2")
	assertRange(t, "custom hMaxRequestTimes", requestOnly.HMaxRequestTimes, 10, 20)
	assertRange(t, "default hMaxReusableSecs", requestOnly.HMaxReusableSecs, 1800, 3000)
}

func TestResolveXmuxPreservesExplicitZeroReuseLimitsFromProto(t *testing.T) {
	cMaxZero := resolveXmuxConfig(&XmuxConfig{CMaxReuseTimes: &RangeConfig{}}, "2")
	assertRange(t, "cMax zero", cMaxZero.CMaxReuseTimes, 0, 0)
	assertRange(t, "cMax request default", cMaxZero.HMaxRequestTimes, 600, 900)
	assertRange(t, "cMax reusable default", cMaxZero.HMaxReusableSecs, 1800, 3000)

	requestZero := resolveXmuxConfig(&XmuxConfig{HMaxRequestTimes: &RangeConfig{}}, "2")
	assertRange(t, "request zero", requestZero.HMaxRequestTimes, 0, 0)
	assertRange(t, "request zero reusable default", requestZero.HMaxReusableSecs, 1800, 3000)

	reusableZero := resolveXmuxConfig(&XmuxConfig{HMaxReusableSecs: &RangeConfig{}}, "2")
	assertRange(t, "reusable zero request default", reusableZero.HMaxRequestTimes, 600, 900)
	assertRange(t, "reusable zero", reusableZero.HMaxReusableSecs, 0, 0)
}

func TestResolveInvalidDirectProtoFallsBackSafely(t *testing.T) {
	resolved := resolveXmuxConfig(&XmuxConfig{
		MaxConcurrency: &RangeConfig{From: -2, To: 5},
		MaxConnections: &RangeConfig{From: 0, To: 4},
	}, "3")
	assertRange(t, "maxConcurrency", resolved.MaxConcurrency, 64, 96)
	assertRange(t, "maxConnections", resolved.MaxConnections, 2, 2)
}

func TestExplicitLegacyLookingShapeRemainsExplicit(t *testing.T) {
	explicit := &XmuxConfig{
		MaxConcurrency:   &RangeConfig{},
		MaxConnections:   &RangeConfig{From: 3, To: 3},
		CMaxReuseTimes:   &RangeConfig{},
		HMaxRequestTimes: &RangeConfig{From: 600, To: 900},
		HMaxReusableSecs: &RangeConfig{From: 1800, To: 3000},
	}
	for _, version := range []string{"1.1", "2", "3"} {
		resolved := resolveXmuxConfig(explicit, version)
		assertRange(t, version+" maxConnections", resolved.MaxConnections, 3, 3)
	}
	assertRange(t, "explicit input maxConnections", explicit.MaxConnections, 3, 3)
}

func TestXmuxRangesKeepHistoricalHalfOpenSampling(t *testing.T) {
	for range 1000 {
		if value := (&RangeConfig{From: 1, To: 2}).rand(); value != 1 {
			t.Fatalf("half-open sample = %d, want 1", value)
		}
	}
	if value := (&RangeConfig{From: 64, To: 64}).rand(); value != 64 {
		t.Fatalf("fixed sample = %d, want 64", value)
	}
}

func TestDecideHTTPVersionForXmuxDefaults(t *testing.T) {
	tests := []struct {
		name    string
		tls     *tls.Config
		reality *reality.Config
		want    string
	}{
		{name: "cleartext", want: "1.1"},
		{name: "TLS default", tls: &tls.Config{}, want: "2"},
		{name: "TLS multiple ALPN", tls: &tls.Config{NextProtocol: []string{"h2", "http/1.1"}}, want: "2"},
		{name: "explicit H1", tls: &tls.Config{NextProtocol: []string{"http/1.1"}}, want: "1.1"},
		{name: "explicit H3", tls: &tls.Config{NextProtocol: []string{"h3"}}, want: "3"},
		{name: "REALITY", tls: &tls.Config{NextProtocol: []string{"h3"}}, reality: &reality.Config{}, want: "2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := decideHTTPVersion(test.tls, test.reality); got != test.want {
				t.Fatalf("decideHTTPVersion() = %q, want %q", got, test.want)
			}
		})
	}
}
