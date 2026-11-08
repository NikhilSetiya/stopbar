package gateway

import (
	"sync"
	"time"
)

// rateLimiter is a per-identity fixed-window request cap (CS-103, FR-NFR). A
// zero limit is unlimited. In-memory and per-process; a distributed limit is
// future work. It bounds how fast one identity can hit the engine, independent
// of the value/velocity caps the limiter enforces on the actions themselves.
type rateLimiter struct {
	perMin int
	mu     sync.Mutex
	window time.Time
	counts map[string]int
}

func newRateLimiter(perMin int) *rateLimiter {
	return &rateLimiter{perMin: perMin, counts: map[string]int{}}
}

// allow records a request for key in the current minute and reports whether it
// is within the cap.
func (rl *rateLimiter) allow(key string, now time.Time) bool {
	if rl == nil || rl.perMin <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if w := now.Truncate(time.Minute); w != rl.window {
		rl.window = w
		rl.counts = map[string]int{}
	}
	rl.counts[key]++
	return rl.counts[key] <= rl.perMin
}
