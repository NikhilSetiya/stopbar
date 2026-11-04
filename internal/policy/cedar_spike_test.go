package policy

// CS-007 Cedar spike. These tests pin the cedar-go behaviours Stopbar relies
// on (or must defend against); the findings are written up in
// docs/adr/0001-cedar.md. They exercise the real starter policy and schema
// under examples/policies.

import (
	"os"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
)

const (
	policyFile = "../../examples/policies/agent-wallet.cedar"
	schemaFile = "../../examples/policies/stopbar.cedarschema"
)

type spikeOutcome string

// spikeBundle is the LLD §5.2 split: forbid policies annotated
// @outcome("escalate") live in their own set, everything else in the main set.
type spikeBundle struct{ main, escalate *cedar.PolicySet }

func loadSpikeBundle(t testing.TB) spikeBundle {
	t.Helper()
	src, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	all, err := cedar.NewPolicySetFromBytes(policyFile, src)
	if err != nil {
		t.Fatal(err)
	}
	b := spikeBundle{main: cedar.NewPolicySet(), escalate: cedar.NewPolicySet()}
	for autoID, p := range all.All() {
		// cedar-go names policies policy0..N; @id is only an annotation.
		id := autoID
		if named, ok := p.Annotations()["id"]; ok {
			id = cedar.PolicyID(named)
		}
		out, has := p.Annotations()["outcome"]
		switch {
		case p.Effect() == cedar.Forbid && out == "escalate":
			b.escalate.Add(id, p)
		case p.Effect() == cedar.Forbid && (out == "deny" || !has):
			b.main.Add(id, p) // unannotated forbid defaults to deny
		case p.Effect() == cedar.Permit && !has:
			b.main.Add(id, p)
		default:
			t.Fatalf("policy %s: unsupported effect/@outcome combination %v/%q", id, p.Effect(), out)
		}
	}
	return b
}

// evaluate implements deny > escalate > allow with default deny, failing
// closed on any evaluation error in either set.
func (b spikeBundle) evaluate(req cedar.Request) (spikeOutcome, []cedar.PolicyID) {
	d, diag := cedar.Authorize(b.main, nil, req)
	if len(diag.Errors) > 0 {
		return "deny:FAIL_CLOSED_POLICY", nil
	}
	if d == cedar.Deny {
		return "deny", reasons(diag)
	}
	// Escalate set has no permits, so "matched" means a forbid fired.
	_, ediag := cedar.Authorize(b.escalate, nil, req)
	if len(ediag.Errors) > 0 {
		return "deny:FAIL_CLOSED_POLICY", nil
	}
	if len(ediag.Reasons) > 0 {
		return "escalate", reasons(ediag)
	}
	return "allow", reasons(diag)
}

func reasons(d cedar.Diagnostic) []cedar.PolicyID {
	var ids []cedar.PolicyID
	for _, r := range d.Reasons {
		ids = append(ids, r.PolicyID)
	}
	return ids
}

func dec(t testing.TB, s string) cedar.Decimal {
	t.Helper()
	d, err := types.ParseDecimal(s)
	if err != nil {
		t.Fatalf("ParseDecimal(%q): %v", s, err)
	}
	return d
}

func strs(v ...string) cedar.Set {
	vals := make([]cedar.Value, len(v))
	for i, s := range v {
		vals[i] = cedar.String(s)
	}
	return cedar.NewSet(vals...)
}

// benignCtx is a fully populated, schema-valid context for a small,
// untainted transfer to a known destination.
func benignCtx(t testing.TB) cedar.RecordMap {
	return cedar.RecordMap{
		"amount_usd":            dec(t, "25.00"),
		"pct_of_balance":        dec(t, "0.05"),
		"price_stale":           cedar.False,
		"taint":                 strs(),
		"flags":                 strs(),
		"dest_known":            cedar.True,
		"dest_similar_to_known": cedar.False,
		"vel_1h_usd":            dec(t, "0.0"),
		"vel_24h_usd":           dec(t, "0.0"),
		"vel_1h_count":          cedar.Long(0),
	}
}

func request(action string, ctx cedar.RecordMap) cedar.Request {
	return cedar.Request{
		Principal: cedar.NewEntityUID("Stopbar::Agent", "agent-1"),
		Action:    cedar.NewEntityUID("Stopbar::Action", cedar.String(action)),
		Resource:  cedar.NewEntityUID("Stopbar::Wallet", "w-1"),
		Context:   cedar.NewRecord(ctx),
	}
}

func TestSpikeOutcomeCombination(t *testing.T) {
	b := loadSpikeBundle(t)
	tests := []struct {
		name   string
		action string
		mut    func(cedar.RecordMap)
		want   spikeOutcome
		policy cedar.PolicyID // a policy expected among the reasons
	}{
		{"benign transfer", "transfer", nil, "allow", "base-permit"},
		{"tainted to unknown dest", "transfer", func(c cedar.RecordMap) {
			c["taint"], c["dest_known"] = strs("untrusted_onchain"), cedar.False
		}, "deny", "taint-unknown-destination"},
		{"tainted to known dest", "transfer", func(c cedar.RecordMap) {
			c["taint"] = strs("untrusted_web")
		}, "allow", "base-permit"},
		{"large share of balance", "transfer", func(c cedar.RecordMap) {
			c["pct_of_balance"] = dec(t, "0.2001")
		}, "escalate", "large-share-of-balance"},
		{"exactly 20% does not escalate", "transfer", func(c cedar.RecordMap) {
			c["pct_of_balance"] = dec(t, "0.20")
		}, "allow", "base-permit"},
		{"deny beats escalate", "transfer", func(c cedar.RecordMap) {
			c["pct_of_balance"] = dec(t, "0.9")
			c["flags"] = strs("delegatecall")
		}, "deny", "delegatecall"},
		{"stale price", "transfer", func(c cedar.RecordMap) { c["price_stale"] = cedar.True }, "escalate", "stale-price"},
		{"address poisoning", "transfer", func(c cedar.RecordMap) {
			c["dest_known"], c["dest_similar_to_known"] = cedar.False, cedar.True
		}, "escalate", "address-poisoning"},
		{"opaque contract call", "contract_call", func(c cedar.RecordMap) {
			c["flags"] = strs("opaque")
		}, "escalate", "unknown-call"},
		{"unlimited approval", "approve", func(c cedar.RecordMap) {
			c["flags"] = strs("unlimited_approval")
		}, "deny", "unlimited-approval"},
		// Finding: base-permit omits "approve", so even a bounded approval is
		// default-denied. Correct fail-safe, but the policy pack must decide.
		{"bounded approval has no permit", "approve", nil, "deny", ""},
		{"tool_call has no permit", "tool_call", nil, "deny", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := benignCtx(t)
			if tt.mut != nil {
				tt.mut(ctx)
			}
			got, ids := b.evaluate(request(tt.action, ctx))
			if got != tt.want {
				t.Fatalf("outcome = %q (reasons %v), want %q", got, ids, tt.want)
			}
			if tt.policy != "" && !containsID(ids, tt.policy) {
				t.Fatalf("reasons %v do not include %q", ids, tt.policy)
			}
		})
	}
}

func containsID(ids []cedar.PolicyID, id cedar.PolicyID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// TestSpikeEvalErrorsAreSkipped documents the most important finding: cedar-go
// drops a policy whose condition errors and keeps going. A forbid that errors
// does not forbid, so raw Cedar fails OPEN. The engine must treat any
// Diagnostic.Errors as FAIL_CLOSED_POLICY, and validate requests up front.
func TestSpikeEvalErrorsAreSkipped(t *testing.T) {
	ps, err := cedar.NewPolicySetFromBytes("inline", []byte(`
		permit (principal, action, resource);
		forbid (principal, action, resource) when { context.pct_of_balance.greaterThan(decimal("0.20")) };`))
	if err != nil {
		t.Fatal(err)
	}
	// pct_of_balance missing entirely (e.g. balance enricher returned nothing).
	req := request("transfer", cedar.RecordMap{})
	d, diag := cedar.Authorize(ps, nil, req)
	if d != cedar.Allow || len(diag.Errors) == 0 {
		t.Fatalf("expected raw Cedar to Allow with errors (fail-open); got %v, %d errors", d, len(diag.Errors))
	}

	b := loadSpikeBundle(t)
	ctx := benignCtx(t)
	delete(ctx, "pct_of_balance")
	if got, _ := b.evaluate(request("transfer", ctx)); got != "deny:FAIL_CLOSED_POLICY" {
		t.Fatalf("combiner outcome = %q, want fail-closed deny", got)
	}

	// Wrong type (a string where a decimal is expected) behaves the same way.
	ctx = benignCtx(t)
	ctx["pct_of_balance"] = cedar.String("0.9")
	if got, _ := b.evaluate(request("transfer", ctx)); got != "deny:FAIL_CLOSED_POLICY" {
		t.Fatalf("combiner outcome = %q, want fail-closed deny", got)
	}
}

func loadValidator(t testing.TB) *validate.Validator {
	t.Helper()
	src, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var s schema.Schema
	if err := s.UnmarshalCedar(src); err != nil {
		t.Fatal(err)
	}
	r, err := s.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return validate.New(r)
}

// TestSpikeSchemaValidation: the (experimental) x/exp validator type-checks
// the starter policy at load time and rejects malformed requests before eval.
func TestSpikeSchemaValidation(t *testing.T) {
	v := loadValidator(t)
	src, _ := os.ReadFile(policyFile)
	ps, err := cedar.NewPolicySetFromBytes(policyFile, src)
	if err != nil {
		t.Fatal(err)
	}
	for id, p := range ps.All() {
		if err := v.Policy(string(id), (*xast.Policy)(p.AST())); err != nil {
			t.Errorf("starter policy %s fails strict validation: %v", id, err)
		}
	}

	bad, err := cedar.NewPolicySetFromBytes("bad", []byte(
		`forbid (principal, action, resource) when { context.pct_of_balance > decimal("0.20") };`))
	if err != nil {
		t.Fatal(err)
	}
	for id, p := range bad.All() {
		if err := v.Policy(string(id), (*xast.Policy)(p.AST())); err == nil {
			t.Errorf("`>` on decimals should fail validation (needs .greaterThan)")
		}
	}

	if err := v.Request(request("transfer", benignCtx(t))); err != nil {
		t.Errorf("benign request rejected: %v", err)
	}
	ctx := benignCtx(t)
	delete(ctx, "pct_of_balance")
	if err := v.Request(request("transfer", ctx)); err == nil {
		t.Errorf("request missing a required context attribute was accepted")
	}
	ctx = benignCtx(t)
	ctx["taint"] = cedar.String("untrusted_web")
	if err := v.Request(request("transfer", ctx)); err == nil {
		t.Errorf("request with non-set taint was accepted")
	}
}

// TestSpikeDecimalLimits: Cedar decimal is int64 with 4 fractional digits
// (about ±9.2e14) and its parser insists on a decimal point. Stopbar's
// decimal-string amounts therefore need an explicit, conservative conversion,
// and raw on-chain units (wei) can never be handed to Cedar.
func TestSpikeDecimalLimits(t *testing.T) {
	for _, s := range []string{"1.0", "0.2001", "922337203685477.5807", "-0.5"} {
		if _, err := types.ParseDecimal(s); err != nil {
			t.Errorf("ParseDecimal(%q) unexpectedly failed: %v", s, err)
		}
	}
	for _, s := range []string{
		"100",                   // no decimal point
		"0.12345",               // > 4 fractional digits
		"1000000000000000000.0", // 1 ETH in wei: overflows
		"922337203685477.5808",  // just past max
		"1e3",                   // exponent form
	} {
		if _, err := types.ParseDecimal(s); err == nil {
			t.Errorf("ParseDecimal(%q) unexpectedly succeeded", s)
		}
	}
}

// BenchmarkSpikeEvaluate measures the full two-set evaluation against the
// LLD §13 policy budget of 2 ms.
func BenchmarkSpikeEvaluate(b *testing.B) {
	bundle := loadSpikeBundle(b)
	ctx := benignCtx(b)
	ctx["pct_of_balance"] = dec(b, "0.3")
	req := request("transfer", ctx)
	b.ReportAllocs()
	for b.Loop() {
		if got, _ := bundle.evaluate(req); got != "escalate" {
			b.Fatal(got)
		}
	}
}
