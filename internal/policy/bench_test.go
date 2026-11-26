package policy

import (
	"context"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// BenchmarkEvaluate: the starter bundle on an allowed transfer and on
// CS-2026-0002's whole-balance transfer (escalate) (CS-197). LLD §13's
// policy budget is 2 ms.
func BenchmarkEvaluate(b *testing.B) {
	bundle, err := Load(starterDir)
	if err != nil {
		b.Fatal(err)
	}
	s := func(v string) *string { return &v }
	escalate := baseContext()
	escalate.AmountUSD, escalate.PctOfBalance = s("250091.1"), s("1")
	for _, tc := range []struct {
		name string
		er   model.EnrichedRequest
		want model.Outcome
	}{{"allow", baseContext(), model.Allow}, {"escalate", escalate, model.Escalate}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if pr, err := bundle.Evaluate(context.Background(), tc.er); err != nil || pr.Outcome != tc.want {
					b.Fatalf("%+v %v", pr, err)
				}
			}
		})
	}
}
