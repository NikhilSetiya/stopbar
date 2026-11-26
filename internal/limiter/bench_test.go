package limiter

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkReserve: one reservation checked against wallet, tenant and
// per-tx caps, in memory (the durable write is BenchmarkAppend in
// internal/audit) (CS-197). Caps are sized never to bite.
func BenchmarkReserve(b *testing.B) {
	c := newClock()
	l := newLimiter(b, c,
		Rule{Scope: ScopeWallet, Window: "tx", MaxUSD: "10000"},
		Rule{Scope: ScopeWallet, Window: "1h", MaxUSD: "1000000000", MaxCount: 1 << 40},
		Rule{Scope: ScopeTenant, Window: "1h", MaxUSD: "1000000000"})
	er := req(walletA, dest, "4.77", "1000", true)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		c.Advance(time.Millisecond)
		if err := l.Reserve(bg, fmt.Sprint("r", i), er, time.Minute, nil); err != nil {
			b.Fatal(err)
		}
	}
}
