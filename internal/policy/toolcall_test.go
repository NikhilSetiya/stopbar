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

const bankingDir = "../../research/agentdojo/policies/banking"

var _ engine.Enricher = (*SessionTaint)(nil)

func copyBundle(t *testing.T, edit func(name string, b []byte) []byte) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(bankingDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(bankingDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			b = edit(e.Name(), b)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestTrustMapIsPartOfTheBundleHash(t *testing.T) {
	base := mustLoad(t, copyBundle(t, nil)).Hash()
	relabelled := copyBundle(t, func(name string, b []byte) []byte {
		if name != TrustFile {
			return b
		}
		// Move one tool from untrusted to trusted output.
		return []byte(strings.Replace(string(b), `"untrusted_output_tools": [
    "read_file",`, `"untrusted_output_tools": [`, 1))
	})
	if got := mustLoad(t, relabelled).Hash(); got == base {
		t.Fatal("changing a trust label did not change the bundle hash")
	}
}

func TestTrustMapValidation(t *testing.T) {
	for name, bad := range map[string]string{
		"unknown field":                    `{"principle":"p","read_only_tools":["a"],"state_changing_tools":[],"untrusted_output_tools":[],"account_identity_tools":[],"rationale":{"a":"x"},"extra":1}`,
		"tool in both lists":               `{"principle":"p","read_only_tools":["a"],"state_changing_tools":["a"],"untrusted_output_tools":[],"account_identity_tools":[],"rationale":{"a":"x"}}`,
		"untrusted tool not declared":      `{"principle":"p","read_only_tools":["a"],"state_changing_tools":[],"untrusted_output_tools":["b"],"account_identity_tools":[],"rationale":{"a":"x"}}`,
		"identity tool not state-changing": `{"principle":"p","read_only_tools":["a"],"state_changing_tools":[],"untrusted_output_tools":[],"account_identity_tools":["a"],"rationale":{"a":"x"}}`,
		"missing principle":                `{"read_only_tools":["a"],"state_changing_tools":[],"untrusted_output_tools":[],"account_identity_tools":[],"rationale":{"a":"x"}}`,
		"missing rationale":                `{"principle":"p","read_only_tools":["a"],"state_changing_tools":[],"untrusted_output_tools":[],"account_identity_tools":[],"rationale":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := copyBundle(t, func(n string, b []byte) []byte {
				if n == TrustFile {
					return []byte(bad)
				}
				return b
			})
			if _, err := Load(dir); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// toolReq is one call in a synthetic session (no AgentDojo task involved).
func toolReq(session, tool string) model.EnrichedRequest {
	return model.EnrichedRequest{
		Request: model.ActionRequest{Tenant: "t", Actor: model.Actor{AgentID: "agent", SessionID: session},
			Action: model.Action{Kind: model.KindToolCall, Tool: &tool, Args: map[string]any{}}},
		Intent: model.IntentSummary{Kind: "tool_call", Flags: []string{}},
		Taint:  []string{"trusted_user"},
	}
}

func TestBankingPackSessionTaint(t *testing.T) {
	b := mustLoad(t, bankingDir)
	st := &SessionTaint{Bundle: b}
	call := func(session, tool string) (model.Outcome, []string) {
		t.Helper()
		er := toolReq(session, tool)
		if err := st.Enrich(context.Background(), &er); err != nil {
			t.Fatal(err)
		}
		pr, err := b.Evaluate(context.Background(), er)
		if err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, r := range pr.Reasons {
			ids = append(ids, r.PolicyID)
		}
		return pr.Outcome, ids
	}
	// Clean session: every declared tool is allowed.
	for _, tc := range []struct {
		tool string
		want model.Outcome
	}{
		{"get_balance", model.Allow}, {"get_iban", model.Allow}, {"get_user_info", model.Allow},
		{"send_money", model.Allow}, {"schedule_transaction", model.Allow}, {"update_scheduled_transaction", model.Allow},
		// Amendment 2: no identity-change rule in the pilot pack.
		{"update_password", model.Allow}, {"update_user_info", model.Allow},
	} {
		if got, ids := call("clean", tc.tool); got != tc.want {
			t.Errorf("clean session %s: %s %v, want %s", tc.tool, got, ids, tc.want)
		}
	}
	// The untrusted read itself is allowed (its own output is not yet in context)...
	if got, _ := call("s1", "get_most_recent_transactions"); got != model.Allow {
		t.Fatalf("untrusted read: %s", got)
	}
	// ...and every state change after it is denied; reads stay allowed.
	for _, tool := range []string{"send_money", "schedule_transaction", "update_scheduled_transaction", "update_password", "update_user_info"} {
		if got, ids := call("s1", tool); got != model.Deny || ids[0] != "tainted-state-change" {
			t.Errorf("tainted %s: %s %v", tool, got, ids)
		}
	}
	if got, _ := call("s1", "get_balance"); got != model.Allow {
		t.Error("reads must stay allowed in a tainted session")
	}
	// Each untrusted-output tool taints its session; sessions are independent.
	for _, reader := range []string{"read_file", "get_scheduled_transactions"} {
		call("s-"+reader, reader)
		if got, _ := call("s-"+reader, "send_money"); got != model.Deny {
			t.Errorf("%s did not taint the session", reader)
		}
	}
	if got, _ := call("other-session", "send_money"); got != model.Allow {
		t.Error("taint leaked across sessions")
	}
}

func TestToolCallsFailClosed(t *testing.T) {
	b := mustLoad(t, bankingDir)
	st := &SessionTaint{Bundle: b}
	er := toolReq("s", "transfer_everything") // not declared
	if err := st.Enrich(context.Background(), &er); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Evaluate(context.Background(), er); err == nil {
		t.Fatal("undeclared tool evaluated")
	}
	er = toolReq("", "send_money") // no session to track taint in
	if err := st.Enrich(context.Background(), &er); err == nil {
		t.Fatal("tool call without a session accepted")
	}
	if _, err := mustLoad(t, starterDir).Evaluate(context.Background(), toolReq("s", "send_money")); err == nil {
		t.Fatal("a bundle without a trust map evaluated a tool call")
	}
}
