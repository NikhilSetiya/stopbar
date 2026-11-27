package engine

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// TestAbandonedStagesShareNothing (CS-197): a stage that times out is
// abandoned but keeps running. Run under -race, this keeps timed-out stages
// reading and writing what they were given (a signer reading the decision,
// an enricher appending flags and taint) while the engine goes on to deny
// and audit. Any shared memory is a race the detector reports. Before the
// fix, the Sign closure read d while evaluate set d.ReservationID = nil.
func TestAbandonedStagesShareNothing(t *testing.T) {
	var wg sync.WaitGroup
	defer wg.Wait() // let every abandoned stage finish touching its inputs before the test ends

	slowSign := signFunc(func(ctx context.Context, d model.Decision) (string, error) {
		wg.Add(1)
		defer wg.Done()
		<-ctx.Done() // past the stage timeout: the engine has moved on
		for range 50 {
			_, _ = json.Marshal(d) // reads every field, Reasons and ReservationID included
			time.Sleep(time.Millisecond)
		}
		return "aGVhZA.cGF5bG9hZA.c2ln", nil
	})
	slowEnrich := enrichFunc(func(ctx context.Context, er *model.EnrichedRequest) error {
		wg.Add(1)
		defer wg.Done()
		<-ctx.Done()
		for range 50 {
			er.Intent.Flags = append(er.Intent.Flags, "late")
			er.Taint = append(er.Taint, "late")
			er.Velocity["1h"] = model.Velocity{USD: "1"}
			time.Sleep(time.Millisecond)
		}
		return nil
	})
	flagged := fakeDecoder{fn: func(_ context.Context, a model.Action) (model.IntentSummary, error) {
		return model.IntentSummary{Kind: string(a.Kind), Human: "fake", Flags: make([]string, 1, 8)}, nil // spare capacity invites a shared append
	}}

	argsEnrich := enrichFunc(func(ctx context.Context, er *model.EnrichedRequest) error {
		wg.Add(1)
		defer wg.Done()
		<-ctx.Done()
		for range 50 { // review finding 4: Action.Args reached the caller's request through a shallow copy
			er.Request.Action.Args["limit"] = 1
			er.Request.Action.Args["late"] = []any{"x"}
			time.Sleep(time.Millisecond)
		}
		return nil
	})

	for _, tc := range []struct {
		name    string
		fixture string
		set     func(*rig)
		code    string
	}{
		{"signer times out", "action_request.evm_tx.json", func(r *rig) { r.cfg.Signer = slowSign }, CodeSigner},
		{"enricher times out", "action_request.evm_tx.json", func(r *rig) {
			r.cfg.Decoders = []Decoder{flagged}
			r.cfg.Enrichers = []Enricher{slowEnrich}
		}, CodeEnrich},
		{"enricher mutating Action.Args times out", "action_request.tool_call.json", func(r *rig) {
			r.cfg.Enrichers = []Enricher{argsEnrich}
		}, CodeEnrich},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig()
			r.cfg.StageTimeout = 5 * time.Millisecond
			tc.set(r)
			e := r.engine(t)
			for i := range 4 {
				req := fixtureRequest(t, tc.fixture)
				req.ID = req.ID + string(rune('a'+i))
				d := evaluate(t, e, req)
				for range 20 { // the caller (the gateway's request record) reads its request after the answer
					_, _ = json.Marshal(req)
					time.Sleep(time.Millisecond)
				}
				if d.Outcome != model.Deny || d.Token != "" || !hasCode(d, tc.code) {
					t.Fatalf("got %s %v token=%q, want deny %s with no token", d.Outcome, d.Reasons, d.Token, tc.code)
				}
				_, _ = json.Marshal(d) // the engine's own reads of what it returned
			}
		})
	}
}

func hasCode(d model.Decision, code string) bool {
	for _, r := range d.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}
