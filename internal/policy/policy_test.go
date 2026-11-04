package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

var _ engine.Policy = (*Bundle)(nil)

const starterDir = "../../examples/policies"

func writeBundle(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func starterSchema(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(starterDir, "stopbar.cedarschema"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoadStarterBundle(t *testing.T) {
	b, err := Load(starterDir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.Hash(), "sha256:") || len(b.Hash()) != 71 {
		t.Fatalf("hash %q", b.Hash())
	}
}

func TestBundleHashIsOrderIndependentAndContentBound(t *testing.T) {
	schema := starterSchema(t)
	a := writeBundle(t, map[string]string{"s.cedarschema": schema, "a.cedar": permitAll, "b.cedar": denyD})
	b := writeBundle(t, map[string]string{"b.cedar": denyD, "s.cedarschema": schema, "a.cedar": permitAll})
	c := writeBundle(t, map[string]string{"s.cedarschema": schema, "a.cedar": permitAll, "b.cedar": denyD + "\n"})
	ha, hb, hc := mustLoad(t, a).Hash(), mustLoad(t, b).Hash(), mustLoad(t, c).Hash()
	if ha != hb {
		t.Fatalf("hash depends on file order: %s vs %s", ha, hb)
	}
	if ha == hc {
		t.Fatal("hash ignores a content change")
	}
}

func mustLoad(t *testing.T, dir string) *Bundle {
	t.Helper()
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	permitAll = `@id("p") permit (principal, action, resource) when { context.flags.contains("p") };`
	denyD     = `@id("d") @outcome("deny") forbid (principal, action, resource) when { context.flags.contains("d") };`
	escE      = `@id("e") @outcome("escalate") forbid (principal, action, resource) when { context.flags.contains("e") };`
)

func TestLoadRejectsInvalidBundles(t *testing.T) {
	schema := starterSchema(t)
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no schema", map[string]string{"a.cedar": permitAll}, "exactly one .cedarschema"},
		{"two schemas", map[string]string{"a.cedarschema": schema, "b.cedarschema": schema, "a.cedar": permitAll}, "exactly one .cedarschema"},
		{"no policies", map[string]string{"s.cedarschema": schema}, "no .cedar files"},
		{"missing @id", map[string]string{"s.cedarschema": schema, "a.cedar": "\n\npermit (principal, action, resource);"}, "a.cedar:3: policy has no @id"},
		{"duplicate @id across files", map[string]string{"s.cedarschema": schema, "a.cedar": permitAll, "b.cedar": "\n" + strings.Replace(denyD, `"d"`, `"p"`, 1)}, `b.cedar:2: duplicate @id "p" (first defined at a.cedar:1)`},
		{"@outcome on permit", map[string]string{"s.cedarschema": schema, "a.cedar": `@id("x") @outcome("deny") permit (principal, action, resource);`}, "only valid on forbid"},
		{"unknown @outcome", map[string]string{"s.cedarschema": schema, "a.cedar": `@id("x") @outcome("maybe") forbid (principal, action, resource);`}, `got "maybe"`},
		{"unknown annotation", map[string]string{"s.cedarschema": schema, "a.cedar": `@id("x") @severity("high") forbid (principal, action, resource);`}, "unknown annotation @severity"},
		{"schema violation (> on decimal)", map[string]string{"s.cedarschema": schema, "a.cedar": "\n" + `@id("x") forbid (principal, action, resource) when { context.pct_of_balance > decimal("0.2") };`}, "a.cedar:2: policy x fails schema validation"},
		{"unknown context attribute", map[string]string{"s.cedarschema": schema, "a.cedar": `@id("x") forbid (principal, action, resource) when { context.typo_known };`}, "policy x fails schema validation"},
		{"parse error", map[string]string{"s.cedarschema": schema, "a.cedar": `@id("x") permit (principal, action, resource`}, "a.cedar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeBundle(t, tt.files))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// baseContext is a complete, schema-valid enriched request for a small
// untainted transfer to a known destination.
func baseContext() model.EnrichedRequest {
	chain := uint64(8453)
	s := func(v string) *string { return &v }
	return model.EnrichedRequest{
		Request: model.ActionRequest{
			ID: "r", Tenant: "acme", Actor: model.Actor{AgentID: "agent-1"},
			Action: model.Action{Kind: model.KindEVMTx, ChainID: &chain, From: "0x2222222222222222222222222222222222222222", To: "0x3333333333333333333333333333333333333333", ValueWei: "0"},
		},
		Intent:       model.IntentSummary{Kind: "transfer", Flags: []string{}},
		AmountUSD:    s("25.00"),
		PctOfBalance: s("0.05"),
		Velocity:     map[string]model.Velocity{"1h": {USD: "0"}, "24h": {USD: "0"}},
		Destination:  model.DestinationInfo{Known: true},
		Taint:        []string{},
	}
}

// TestCombinerAllCombinations: deny > escalate > allow, default deny, and
// only the winning set's policies appear as reasons.
func TestCombinerAllCombinations(t *testing.T) {
	b := mustLoad(t, writeBundle(t, map[string]string{"s.cedarschema": starterSchema(t), "p.cedar": permitAll + "\n" + denyD + "\n" + escE}))
	for _, tt := range []struct {
		flags   string
		outcome model.Outcome
		reason  string // policy id, or code for default deny
	}{
		{"", model.Deny, CodeDefaultDeny},
		{"e", model.Deny, CodeDefaultDeny}, // escalate without permit is still default deny
		{"d", model.Deny, "d"},
		{"de", model.Deny, "d"},
		{"p", model.Allow, ""},
		{"pe", model.Escalate, "e"},
		{"pd", model.Deny, "d"},
		{"pde", model.Deny, "d"},
	} {
		t.Run("flags="+tt.flags, func(t *testing.T) {
			er := baseContext()
			er.Intent.Flags = strings.Split(tt.flags, "")
			if tt.flags == "" {
				er.Intent.Flags = []string{}
			}
			pr, err := b.Evaluate(context.Background(), er)
			if err != nil {
				t.Fatal(err)
			}
			if pr.Outcome != tt.outcome || pr.BundleHash != b.Hash() {
				t.Fatalf("got %+v, want %s", pr, tt.outcome)
			}
			switch tt.reason {
			case "":
				if len(pr.Reasons) != 0 {
					t.Fatalf("allow with reasons %+v", pr.Reasons)
				}
			case CodeDefaultDeny:
				if len(pr.Reasons) != 1 || pr.Reasons[0].Code != CodeDefaultDeny {
					t.Fatalf("reasons %+v", pr.Reasons)
				}
			default:
				if len(pr.Reasons) != 1 || pr.Reasons[0].PolicyID != tt.reason || pr.Reasons[0].Code != engine.CodePolicy {
					t.Fatalf("reasons %+v, want only %s", pr.Reasons, tt.reason)
				}
			}
		})
	}
}

func TestStarterPackSeedAttacks(t *testing.T) {
	b := mustLoad(t, starterDir)
	s := func(v string) *string { return &v }
	// CS-2026-0001: 3,000,000 DRB at $0.058, whole balance, tainted, unknown destination.
	er := baseContext()
	er.AmountUSD, er.PctOfBalance = s("174000"), s("1")
	er.Taint = []string{"untrusted_onchain", "decoded"}
	er.Destination.Known = false
	pr, err := b.Evaluate(context.Background(), er)
	if err != nil || pr.Outcome != model.Deny || len(pr.Reasons) != 1 || pr.Reasons[0].PolicyID != "taint-unknown-destination" {
		t.Fatalf("0001: %+v %v", pr, err)
	}
	// CS-2026-0002: whole balance to a known destination, trusted input.
	er = baseContext()
	er.AmountUSD, er.PctOfBalance = s("250091.1"), s("1")
	er.Taint = []string{"trusted_user"}
	pr, err = b.Evaluate(context.Background(), er)
	if err != nil || pr.Outcome != model.Escalate || len(pr.Reasons) != 1 || pr.Reasons[0].PolicyID != "large-share-of-balance" {
		t.Fatalf("0002: %+v %v", pr, err)
	}
}

func TestEvaluateFailsClosedOnIncompleteContext(t *testing.T) {
	b := mustLoad(t, starterDir)
	for name, mut := range map[string]func(*model.EnrichedRequest){
		"amount missing (stale price)": func(er *model.EnrichedRequest) { er.AmountUSD = nil; er.PriceStale = true },
		"balance share missing":        func(er *model.EnrichedRequest) { er.PctOfBalance = nil },
		"velocity window missing":      func(er *model.EnrichedRequest) { delete(er.Velocity, "24h") },
		"amount not a decimal":         func(er *model.EnrichedRequest) { v := "1e3"; er.AmountUSD = &v },
		"amount beyond Cedar range":    func(er *model.EnrichedRequest) { v := "1000000000000000000"; er.AmountUSD = &v },
		"intent not a policy action":   func(er *model.EnrichedRequest) { er.Intent.Kind = "mint" },
		"tool_call (CS-502)":           func(er *model.EnrichedRequest) { er.Request.Action.Kind = model.KindToolCall },
	} {
		t.Run(name, func(t *testing.T) {
			er := baseContext()
			mut(&er)
			if pr, err := b.Evaluate(context.Background(), er); err == nil {
				t.Fatalf("expected an error (fail closed), got %+v", pr)
			}
		})
	}
}

func TestToCedarDecimalRoundsUp(t *testing.T) {
	for in, want := range map[string]string{
		"0": "0.0", "25": "25.0", "0.20": "0.2", "0.2001": "0.2001", "0.20001": "0.2001",
		"0.00001": "0.0001", "174000": "174000.0", "922337203685477.5807": "922337203685477.5807",
	} {
		d, err := toCedarDecimal(in)
		if err != nil || d.String() != want {
			t.Errorf("%s -> %v %v, want %s", in, d, err, want)
		}
	}
	for _, in := range []string{"", "-1", "1e3", "1/3", "0x10", " 1", "922337203685477.5808", "1."} {
		if _, err := toCedarDecimal(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
