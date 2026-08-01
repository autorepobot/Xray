package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
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
