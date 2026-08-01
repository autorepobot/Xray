package splithttp_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

func Test_GetNormalizedPath(t *testing.T) {
	tests := []struct {
		TestName           string
		Path               string
		SessionIDPlacement string
		SeqPlacement       string
		Expected           string
	}{
		{
			TestName: "default placement keeps trailing slash",
			Path:     "/sh",
			Expected: "/sh/",
		},
		{
			TestName: "query string is stripped",
			Path:     "/?world",
			Expected: "/",
		},
		{
			TestName:           "both off path drops trailing slash",
			Path:               "/stream",
			SessionIDPlacement: "query",
			SeqPlacement:       "query",
			Expected:           "/stream",
		},
		{
			TestName:           "both off path keeps file-like path",
			Path:               "/stream/filename.extension",
			SessionIDPlacement: "query",
			SeqPlacement:       "header",
			Expected:           "/stream/filename.extension",
		},
		{
			TestName:           "seq in path keeps trailing slash",
			Path:               "/stream",
			SessionIDPlacement: "query",
			Expected:           "/stream/",
		},
		{
			TestName:     "session in path keeps trailing slash",
			Path:         "/stream",
			SeqPlacement: "cookie",
			Expected:     "/stream/",
		},
		{
			TestName:           "existing trailing slash preserved",
			Path:               "/stream/",
			SessionIDPlacement: "query",
			SeqPlacement:       "query",
			Expected:           "/stream/",
		},
		{
			TestName:           "root unchanged",
			Path:               "/",
			SessionIDPlacement: "query",
			SeqPlacement:       "query",
			Expected:           "/",
		},
	}
	for _, test := range tests {
		t.Run(test.TestName, func(t *testing.T) {
			c := Config{
				Path:               test.Path,
				SessionIDPlacement: test.SessionIDPlacement,
				SeqPlacement:       test.SeqPlacement,
			}
			assert.Equal(t, test.Expected, c.GetNormalizedPath())
		})
	}
}

func TestInvalidDirectPostSizeFallsBackToDefault(t *testing.T) {
	for _, configured := range []*RangeConfig{
		{From: -1, To: -1},
		{From: 0, To: 5},
		{From: 10, To: 5},
	} {
		got := (&Config{ScMaxEachPostBytes: configured}).GetNormalizedScMaxEachPostBytes()
		if got.From != 1000000 || got.To != 1000000 {
			t.Fatalf("normalized invalid range %#v = %#v, want 1000000", configured, got)
		}
	}
}

func TestDirectRangeConfigurationIsMadeSafe(t *testing.T) {
	streamSecs := (&Config{ScStreamUpServerSecs: &RangeConfig{From: 0, To: 1}}).GetNormalizedScStreamUpServerSecs()
	if streamSecs.From != 20 || streamSecs.To != 80 {
		t.Fatalf("cross-zero stream padding interval = %#v, want default 20-80", streamSecs)
	}
	offSecs := (&Config{ScStreamUpServerSecs: &RangeConfig{From: -2, To: -1}}).GetNormalizedScStreamUpServerSecs()
	if offSecs.From != -2 || offSecs.To != -1 {
		t.Fatalf("negative stream padding interval = %#v, want off range", offSecs)
	}

	chunkSize := (&Config{UplinkChunkSize: &RangeConfig{From: 100, To: -1}}).GetNormalizedUplinkChunkSize()
	if chunkSize.From != 64 || chunkSize.To != 100 {
		t.Fatalf("reversed direct chunk range = %#v, want clamped 64-100", chunkSize)
	}

	sessionConfig := &Config{
		SessionIDTable:  "ab",
		SessionIDLength: &RangeConfig{From: MaxSessionIDLength + 1, To: MaxSessionIDLength + 1},
	}
	if got := sessionConfig.GenerateSessionID(); len(got) != 36 {
		t.Fatalf("unsafe direct session length generated %d bytes, want UUID fallback", len(got))
	}
}
