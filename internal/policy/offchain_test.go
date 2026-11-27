package policy

import (
	"context"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Off-chain signatures (CS-514) map onto the same Cedar actions as their
// on-chain twins, so the starter pack treats a signed Permit2 max like an
// unlimited approve; sign_message never passes as an approval or a call.
func TestStarterPackOffchain(t *testing.T) {
	b := mustLoad(t, starterDir)
	s := func(v string) *string { return &v }
	off := func(kind model.ActionKind, intent string, known bool, usd *string, flags ...string) model.EnrichedRequest {
		er := baseContext()
		er.Request.Action = model.Action{Kind: kind, ChainID: er.Request.Action.ChainID, From: er.Request.Action.From}
		er.Intent.Kind, er.Intent.Flags = intent, append([]string{}, flags...)
		er.AmountUSD, er.PctOfBalance, er.ApprovalUSD = s("0"), s("0"), usd
		er.Destination.Known = known
		return er
	}
	tainted := off(model.KindEVMPersonalSign, "sign_message", false, nil)
	tainted.Taint = []string{"untrusted_web"}
	for name, tt := range map[string]struct {
		er   model.EnrichedRequest
		want model.Outcome
		id   string
	}{
		"permit2 max":                {off(model.KindEVMTypedData, "approve", true, nil, "unlimited_approval"), model.Deny, "unlimited-approval"},
		"permit2 bounded, known":     {off(model.KindEVMTypedData, "approve", true, s("250")), model.Allow, ""},
		"permit2 bounded, long":      {off(model.KindEVMTypedData, "approve", true, s("250"), "long_expiry"), model.Escalate, "long-expiry"},
		"permit2 bounded, unknown":   {off(model.KindEVMTypedData, "approve", false, s("250")), model.Deny, ""},
		"seaport zero consideration": {off(model.KindEVMTypedData, "transfer", false, nil, "zero_consideration"), model.Deny, "zero-consideration"},
		"unknown typed data":         {off(model.KindEVMTypedData, "sign_message", false, nil, "unknown_call"), model.Escalate, "unknown-call"},
		"readable personal_sign":     {off(model.KindEVMPersonalSign, "sign_message", false, nil), model.Allow, ""},
		"raw personal_sign":          {off(model.KindEVMPersonalSign, "sign_message", false, nil, "opaque"), model.Escalate, "unknown-call"},
		"tainted personal_sign":      {tainted, model.Deny, "taint-unknown-destination"},
	} {
		t.Run(name, func(t *testing.T) {
			pr, err := b.Evaluate(context.Background(), tt.er)
			if err != nil || pr.Outcome != tt.want {
				t.Fatalf("got %s %+v %v, want %s", pr.Outcome, pr.Reasons, err, tt.want)
			}
			if tt.id != "" && (len(pr.Reasons) != 1 || pr.Reasons[0].PolicyID != tt.id) {
				t.Fatalf("reasons %+v, want %s", pr.Reasons, tt.id)
			}
		})
	}
	// A personal_sign can't be dressed up as a contract call or an approval.
	for _, intent := range []string{"contract_call", "approve"} {
		if _, err := b.Evaluate(context.Background(), off(model.KindEVMPersonalSign, intent, true, nil)); err == nil {
			t.Errorf("personal_sign as %s evaluated; must fail closed", intent)
		}
	}
}
