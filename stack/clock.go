package stack

import "time"

// Timestamps kept in atomics are monotonic nanoseconds since clockBase, not
// UnixNano: moving the system clock (by hand or by NTP) must neither expire
// every NAT mapping and deadline at once nor keep them alive for hours.
var clockBase = time.Now()

// monoNanos is the current monotonic timestamp; never 0, so 0 can keep
// meaning "unset".
func monoNanos() int64 {
	return int64(time.Since(clockBase)) + 1
}

// monoOf converts t to the same scale. Times from time.Now() (and Add on
// them) carry a monotonic reading, so the result ignores clock changes.
func monoOf(t time.Time) int64 {
	return int64(t.Sub(clockBase)) + 1
}
