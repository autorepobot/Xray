package udphop

import (
	"fmt"
	"math"
	"time"
)

// NormalizeIntervals converts the protobuf/config representation in seconds
// to the effective durations used by NewUDPHopPacketConn. A zero endpoint uses
// the constructor's 30-second default.
func NormalizeIntervals(minSeconds, maxSeconds int64) (time.Duration, time.Duration, error) {
	toDuration := func(name string, seconds int64) (time.Duration, error) {
		if seconds == 0 {
			return 0, nil
		}
		if seconds < 0 {
			return 0, fmt.Errorf("%s must not be negative", name)
		}
		if seconds > math.MaxInt64/int64(time.Second) {
			return 0, fmt.Errorf("%s overflows time.Duration", name)
		}
		return time.Duration(seconds) * time.Second, nil
	}

	minInterval, err := toDuration("UDP hop minimum interval", minSeconds)
	if err != nil {
		return 0, 0, err
	}
	maxInterval, err := toDuration("UDP hop maximum interval", maxSeconds)
	if err != nil {
		return 0, 0, err
	}
	return normalizeIntervals(minInterval, maxInterval)
}

func normalizeIntervals(minInterval, maxInterval time.Duration) (time.Duration, time.Duration, error) {
	if minInterval == 0 {
		minInterval = defaultHopInterval
	}
	if maxInterval == 0 {
		maxInterval = defaultHopInterval
	}
	if minInterval < 5*time.Second {
		return 0, 0, fmt.Errorf("UDP hop minimum interval must be at least 5 seconds")
	}
	if maxInterval < 5*time.Second {
		return 0, 0, fmt.Errorf("UDP hop maximum interval must be at least 5 seconds")
	}
	if maxInterval < minInterval {
		return 0, 0, fmt.Errorf("UDP hop maximum interval must not be less than the minimum interval after applying defaults")
	}
	return minInterval, maxInterval, nil
}
