package udphop

import (
	"math"
	"testing"
	"time"
)

func TestNormalizeIntervals(t *testing.T) {
	tests := []struct {
		name             string
		min, max         int64
		wantMin, wantMax time.Duration
		wantErr          bool
	}{
		{name: "both default", wantMin: 30 * time.Second, wantMax: 30 * time.Second},
		{name: "explicit range", min: 5, max: 10, wantMin: 5 * time.Second, wantMax: 10 * time.Second},
		{name: "default maximum", min: 10, wantMin: 10 * time.Second, wantMax: 30 * time.Second},
		{name: "default minimum", max: 30, wantMin: 30 * time.Second, wantMax: 30 * time.Second},
		{name: "default minimum exceeds maximum", max: 10, wantErr: true},
		{name: "below minimum", min: 4, max: 30, wantErr: true},
		{name: "negative", min: -1, max: 30, wantErr: true},
		{name: "negative overflow", min: math.MinInt64, max: 30, wantErr: true},
		{name: "reversed", min: 30, max: 10, wantErr: true},
		{name: "duration overflow", min: math.MaxInt64, max: math.MaxInt64, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotMin, gotMax, err := NormalizeIntervals(test.min, test.max)
			if (err != nil) != test.wantErr {
				t.Fatalf("NormalizeIntervals(%d, %d) error = %v, wantErr %v", test.min, test.max, err, test.wantErr)
			}
			if err == nil && (gotMin != test.wantMin || gotMax != test.wantMax) {
				t.Fatalf("NormalizeIntervals(%d, %d) = (%s, %s), want (%s, %s)", test.min, test.max, gotMin, gotMax, test.wantMin, test.wantMax)
			}
		})
	}
}
