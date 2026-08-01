package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func buildSplitHTTP(t *testing.T, input string) (*splithttp.Config, error) {
	t.Helper()
	config := new(SplitHTTPConfig)
	if err := json.Unmarshal([]byte(input), config); err != nil {
		return nil, err
	}
	built, err := config.Build()
	if err != nil {
		return nil, err
	}
	return built.(*splithttp.Config), nil
}

func assertProtoRange(t *testing.T, name string, got *splithttp.RangeConfig, from, to int32) {
	t.Helper()
	if got == nil || got.From != from || got.To != to {
		t.Fatalf("%s = %#v, want %d-%d", name, got, from, to)
	}
}

func buildStream(t *testing.T, input string) (*internet.StreamConfig, error) {
	t.Helper()
	config := new(StreamConfig)
	if err := json.Unmarshal([]byte(input), config); err != nil {
		return nil, err
	}
	return config.Build()
}

func TestSplitHTTPXmuxEmptyDefersProtocolDefaults(t *testing.T) {
	built, err := buildSplitHTTP(t, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	assertProtoRange(t, "maxConcurrency", built.Xmux.MaxConcurrency, 0, 0)
	assertProtoRange(t, "maxConnections", built.Xmux.MaxConnections, 0, 0)
	assertProtoRange(t, "hMaxRequestTimes", built.Xmux.HMaxRequestTimes, 600, 900)
	assertProtoRange(t, "hMaxReusableSecs", built.Xmux.HMaxReusableSecs, 1800, 3000)
}

func TestSplitHTTPXmuxLimitCombinations(t *testing.T) {
	tests := []struct {
		name                           string
		input                          string
		concurrencyFrom, concurrencyTo int32
		connectionsFrom, connectionsTo int32
	}{
		{
			name:            "concurrency and auto connections",
			input:           `{"xmux":{"maxConcurrency":"32-64","maxConnections":0}}`,
			concurrencyFrom: 32, concurrencyTo: 64,
		},
		{
			name:            "auto concurrency and connections",
			input:           `{"xmux":{"maxConcurrency":0,"maxConnections":3}}`,
			connectionsFrom: 3, connectionsTo: 3,
		},
		{
			name:            "both explicit",
			input:           `{"xmux":{"maxConcurrency":"16-32","maxConnections":"2-4"}}`,
			concurrencyFrom: 16, concurrencyTo: 32, connectionsFrom: 2, connectionsTo: 4,
		},
		{
			name:            "both off",
			input:           `{"xmux":{"maxConcurrency":-1,"maxConnections":-1}}`,
			concurrencyFrom: -1, concurrencyTo: -1, connectionsFrom: -1, connectionsTo: -1,
		},
		{
			name:            "off concurrency and auto connections",
			input:           `{"xmux":{"maxConcurrency":-1,"maxConnections":0}}`,
			concurrencyFrom: -1, concurrencyTo: -1,
		},
		{
			name:            "auto concurrency and off connections",
			input:           `{"xmux":{"maxConcurrency":0,"maxConnections":-1}}`,
			connectionsFrom: -1, connectionsTo: -1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			built, err := buildSplitHTTP(t, test.input)
			if err != nil {
				t.Fatal(err)
			}
			assertProtoRange(t, "maxConcurrency", built.Xmux.MaxConcurrency, test.concurrencyFrom, test.concurrencyTo)
			assertProtoRange(t, "maxConnections", built.Xmux.MaxConnections, test.connectionsFrom, test.connectionsTo)
			assertProtoRange(t, "hMaxRequestTimes", built.Xmux.HMaxRequestTimes, 600, 900)
			assertProtoRange(t, "hMaxReusableSecs", built.Xmux.HMaxReusableSecs, 1800, 3000)
		})
	}
}

func TestSplitHTTPXmuxHMaxDefaultsAreIndependent(t *testing.T) {
	tests := []struct {
		name                         string
		input                        string
		requestFrom, requestTo       int32
		reusableFrom, reusableTo     int32
		cMaxReuseTimes, keepAliveSec int32
	}{
		{
			name: "cMax reuse does not suppress hMax defaults", input: `{"xmux":{"cMaxReuseTimes":2}}`,
			requestFrom: 600, requestTo: 900, reusableFrom: 1800, reusableTo: 3000, cMaxReuseTimes: 2,
		},
		{
			name: "keepalive does not suppress hMax defaults", input: `{"xmux":{"hKeepAlivePeriod":-1}}`,
			requestFrom: 600, requestTo: 900, reusableFrom: 1800, reusableTo: 3000, keepAliveSec: -1,
		},
		{
			name: "explicit zero request limit", input: `{"xmux":{"hMaxRequestTimes":0}}`,
			requestFrom: 0, requestTo: 0, reusableFrom: 1800, reusableTo: 3000,
		},
		{
			name: "case-insensitive explicit zero request limit", input: `{"xmux":{"HMAXREQUESTTIMES":0}}`,
			requestFrom: 0, requestTo: 0, reusableFrom: 1800, reusableTo: 3000,
		},
		{
			name: "explicit zero reusable limit", input: `{"xmux":{"hMaxReusableSecs":0}}`,
			requestFrom: 600, requestTo: 900, reusableFrom: 0, reusableTo: 0,
		},
		{
			name: "custom request limit", input: `{"xmux":{"hMaxRequestTimes":"10-20"}}`,
			requestFrom: 10, requestTo: 20, reusableFrom: 1800, reusableTo: 3000,
		},
		{
			name: "custom reusable limit", input: `{"xmux":{"hMaxReusableSecs":"30-40"}}`,
			requestFrom: 600, requestTo: 900, reusableFrom: 30, reusableTo: 40,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			built, err := buildSplitHTTP(t, test.input)
			if err != nil {
				t.Fatal(err)
			}
			assertProtoRange(t, "hMaxRequestTimes", built.Xmux.HMaxRequestTimes, test.requestFrom, test.requestTo)
			assertProtoRange(t, "hMaxReusableSecs", built.Xmux.HMaxReusableSecs, test.reusableFrom, test.reusableTo)
			assertProtoRange(t, "cMaxReuseTimes", built.Xmux.CMaxReuseTimes, test.cMaxReuseTimes, test.cMaxReuseTimes)
			if got := built.Xmux.HKeepAlivePeriod; got != int64(test.keepAliveSec) {
				t.Fatalf("hKeepAlivePeriod = %d, want %d", got, test.keepAliveSec)
			}
		})
	}
}

func TestSplitHTTPXmuxHMaxPresenceSurvivesRepeatedBuild(t *testing.T) {
	for _, test := range []struct {
		name                   string
		input                  string
		requestFrom, requestTo int32
	}{
		{name: "omitted request limit", input: `{"xmux":{"maxConcurrency":8}}`, requestFrom: 600, requestTo: 900},
		{name: "explicit zero request limit", input: `{"xmux":{"hMaxRequestTimes":0}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config SplitHTTPConfig
			if err := json.Unmarshal([]byte(test.input), &config); err != nil {
				t.Fatal(err)
			}
			for build := 0; build < 2; build++ {
				message, err := config.Build()
				if err != nil {
					t.Fatal(err)
				}
				assertProtoRange(t, "hMaxRequestTimes", message.(*splithttp.Config).Xmux.HMaxRequestTimes, test.requestFrom, test.requestTo)
			}
		})
	}
}

func TestSplitHTTPXmuxHMaxPresenceSurvivesJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name                     string
		input                    string
		requestFrom, requestTo   int32
		reusableFrom, reusableTo int32
	}{
		{
			name: "omitted fields stay omitted", input: `{"maxConcurrency":8}`,
			requestFrom: 600, requestTo: 900, reusableFrom: 1800, reusableTo: 3000,
		},
		{
			name: "explicit request zero stays explicit", input: `{"hMaxRequestTimes":0}`,
			requestFrom: 0, requestTo: 0, reusableFrom: 1800, reusableTo: 3000,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var first XmuxConfig
			if err := json.Unmarshal([]byte(test.input), &first); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(&first)
			if err != nil {
				t.Fatal(err)
			}
			var roundTripped XmuxConfig
			if err := json.Unmarshal(encoded, &roundTripped); err != nil {
				t.Fatal(err)
			}
			message, err := (&SplitHTTPConfig{Xmux: roundTripped}).Build()
			if err != nil {
				t.Fatal(err)
			}
			built := message.(*splithttp.Config)
			assertProtoRange(t, "hMaxRequestTimes", built.Xmux.HMaxRequestTimes, test.requestFrom, test.requestTo)
			assertProtoRange(t, "hMaxReusableSecs", built.Xmux.HMaxReusableSecs, test.reusableFrom, test.reusableTo)
		})
	}
}

func TestSplitHTTPXmuxRejectsAmbiguousSentinelRanges(t *testing.T) {
	invalid := []string{
		`{"xmux":{"maxConcurrency":"-1-3"}}`,
		`{"xmux":{"maxConnections":"0-3"}}`,
	}
	for _, input := range invalid {
		if _, err := buildSplitHTTP(t, input); err == nil {
			t.Fatalf("invalid XMUX range unexpectedly succeeded: %s", input)
		}
	}
}

func TestSplitHTTPXmuxAcceptsLegacyNegativeOffAliases(t *testing.T) {
	for _, input := range []string{
		`{"xmux":{"maxConcurrency":-2}}`,
		`{"xmux":{"maxConnections":"-3--1"}}`,
		`{"xmux":{"maxConcurrency":"-3-0"}}`,
		`{"xmux":{"maxConnections":"0-1"}}`,
	} {
		if _, err := buildSplitHTTP(t, input); err != nil {
			t.Fatalf("single-semantics XMUX range was rejected for %s: %v", input, err)
		}
	}
}

func TestSplitHTTPXmuxExtraUsesSameValidation(t *testing.T) {
	built, err := buildSplitHTTP(t, `{
		"host":"outer.example",
		"path":"/outer",
		"mode":"packet-up",
		"extra":{"xmux":{"maxConcurrency":8,"maxConnections":2}}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if built.Host != "outer.example" || built.Path != "/outer" || built.Mode != "packet-up" {
		t.Fatalf("outer routing fields were not preserved: host=%q path=%q mode=%q", built.Host, built.Path, built.Mode)
	}
	assertProtoRange(t, "maxConcurrency", built.Xmux.MaxConcurrency, 8, 8)
	assertProtoRange(t, "maxConnections", built.Xmux.MaxConnections, 2, 2)
	assertProtoRange(t, "hMaxRequestTimes", built.Xmux.HMaxRequestTimes, 600, 900)
	assertProtoRange(t, "hMaxReusableSecs", built.Xmux.HMaxReusableSecs, 1800, 3000)

	built, err = buildSplitHTTP(t, `{"extra":{"xmux":{"cMaxReuseTimes":2,"hMaxRequestTimes":0}}}`)
	if err != nil {
		t.Fatal(err)
	}
	assertProtoRange(t, "extra cMaxReuseTimes", built.Xmux.CMaxReuseTimes, 2, 2)
	assertProtoRange(t, "extra hMaxRequestTimes", built.Xmux.HMaxRequestTimes, 0, 0)
	assertProtoRange(t, "extra hMaxReusableSecs", built.Xmux.HMaxReusableSecs, 1800, 3000)

	if _, err := buildSplitHTTP(t, `{"extra":{"xmux":{"maxConcurrency":"0-3"}}}`); err == nil {
		t.Fatal("invalid XMUX range in extra unexpectedly succeeded")
	}
}

func TestSplitHTTPRejectsNegativeBufferedPostCapacity(t *testing.T) {
	if _, err := buildSplitHTTP(t, `{"scMaxBufferedPosts":-1}`); err == nil {
		t.Fatal("negative scMaxBufferedPosts unexpectedly succeeded")
	}
}

func TestSplitHTTPRejectsNonPositivePostSize(t *testing.T) {
	for _, input := range []string{
		`{"scMaxEachPostBytes":-1}`,
		`{"scMaxEachPostBytes":"0-5"}`,
	} {
		if _, err := buildSplitHTTP(t, input); err == nil {
			t.Fatalf("invalid scMaxEachPostBytes unexpectedly succeeded: %s", input)
		}
	}

	built, err := buildSplitHTTP(t, `{"scMaxEachPostBytes":0}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := built.GetNormalizedScMaxEachPostBytes(); got.From != 1000000 || got.To != 1000000 {
		t.Fatalf("default scMaxEachPostBytes = %#v, want 1000000", got)
	}
}

func TestXHTTPBuildDefersH3OnlyCongestionValidation(t *testing.T) {
	_, err := buildStream(t, `{
		"network":"xhttp",
		"xhttpSettings":{},
		"finalmask":{"quicParams":{"congestion":"brutal","brutalUp":"1m"}}
	}`)
	if err != nil {
		t.Fatalf("H1/H2 XHTTP config was rejected by an H3-only validation: %v", err)
	}
}

func TestStreamConfigDefersXHTTPUDPHopValidationUntilH3(t *testing.T) {
	for _, interval := range []string{`"0-10"`, `"4-30"`} {
		input := `{
			"network":"xhttp",
			"xhttpSettings":{},
			"finalmask":{"quicParams":{"udpHop":{"ports":443,"interval":` + interval + `}}}
		}`
		if _, err := buildStream(t, input); err != nil {
			t.Fatalf("H1/H2 XHTTP config was rejected by an H3-only UDP hop validation for %s: %v", interval, err)
		}
	}

	if _, err := buildStream(t, `{
		"network":"hysteria",
		"hysteriaSettings":{"version":2},
		"finalmask":{"quicParams":{"udpHop":{"ports":443,"interval":"0-10"}}}
	}`); err == nil {
		t.Fatal("Hysteria accepted an invalid effective UDP hop interval")
	}

	for _, interval := range []string{`0`, `"5-30"`, `"0-30"`} {
		input := `{
			"network":"hysteria",
			"hysteriaSettings":{"version":2},
			"finalmask":{"quicParams":{"udpHop":{"ports":443,"interval":` + interval + `}}}
		}`
		if _, err := buildStream(t, input); err != nil {
			t.Fatalf("valid Hysteria UDP hop interval %s failed: %v", interval, err)
		}
	}

	if _, err := buildStream(t, `{
		"network":"xhttp",
		"xhttpSettings":{},
		"finalmask":{"quicParams":{"udpHop":{"interval":"0-10"}}}
	}`); err != nil {
		t.Fatalf("unused UDP hop interval was rejected: %v", err)
	}
}

func TestSplitHTTPRejectsStreamPaddingBusyLoopRange(t *testing.T) {
	for _, input := range []string{
		`{"scStreamUpServerSecs":"0-1"}`,
		`{"scStreamUpServerSecs":"-1-1"}`,
	} {
		if _, err := buildSplitHTTP(t, input); err == nil {
			t.Fatalf("cross-zero scStreamUpServerSecs unexpectedly succeeded: %s", input)
		}
	}

	built, err := buildSplitHTTP(t, `{"scStreamUpServerSecs":-1}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := built.GetNormalizedScStreamUpServerSecs(); got.From != -1 || got.To != -1 {
		t.Fatalf("negative off interval = %#v, want -1", got)
	}
}

func TestSplitHTTPSessionIDBoundsAreCheckedBeforeEntropyWork(t *testing.T) {
	invalid := []string{
		`{"sessionIDTable":"Base62","sessionIDLength":"-2147483648--1"}`,
		`{"sessionIDTable":"Base62","sessionIDLength":1048577}`,
		`{"sessionIDTable":"Base62","sessionIDLength":"5-6"}`,
		`{"sessionIDTable":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sessionIDLength":6}`,
	}
	for _, input := range invalid {
		if _, err := buildSplitHTTP(t, input); err == nil {
			t.Fatalf("unsafe session ID configuration unexpectedly succeeded: %s", input)
		}
	}

	if _, err := buildSplitHTTP(t, `{"sessionIDTable":"Base62","sessionIDLength":6}`); err != nil {
		t.Fatalf("valid bounded session ID configuration failed: %v", err)
	}
	if _, err := buildSplitHTTP(t, `{"serverMaxHeaderBytes":16384,"sessionIDTable":"Base62","sessionIDLength":"8192-8193"}`); err != nil {
		t.Fatalf("session ID above the legacy 8 KiB default failed despite an explicit-compatible deployment: %v", err)
	}
	if _, err := buildSplitHTTP(t, `{"serverMaxHeaderBytes":2097152,"sessionIDTable":"Base62","sessionIDLength":"1048576-1048577"}`); err != nil {
		t.Fatalf("safe half-open resource-limit session ID range failed: %v", err)
	}
}

func TestSplitHTTPDownloadSettingsRequireAddressAndXHTTP(t *testing.T) {
	invalid := []string{
		`{"downloadSettings":{"network":"tcp","address":"example.com"}}`,
		`{"downloadSettings":{"network":"xhttp","xhttpSettings":{}}}`,
		`{"downloadSettings":{"network":"xhttp","address":"example.com","xhttpSettings":{}}}`,
	}
	for _, input := range invalid {
		if _, err := buildSplitHTTP(t, input); err == nil {
			t.Fatalf("invalid downloadSettings unexpectedly succeeded: %s", input)
		}
	}

	_, err := buildSplitHTTP(t, `{
		"downloadSettings":{
			"network":"xhttp",
			"address":"download.example",
			"port":443,
			"xhttpSettings":{}
		}
	}`)
	if err != nil {
		t.Fatalf("valid XHTTP downloadSettings failed: %v", err)
	}
}
