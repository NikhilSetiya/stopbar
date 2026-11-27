package engine

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// bundlePolicy escalates on taint-unknown-destination under a bundle whose
// hash the test changes, as a restart on a new bundle would.
type bundlePolicy struct{ hash string }

func (p *bundlePolicy) Evaluate(ctx context.Context, r model.EnrichedRequest) (PolicyResult, error) {
	pr, err := outcome(model.Escalate)(ctx, r)
	pr.BundleHash = p.hash
	return pr, err
}
func (p *bundlePolicy) Hash() string { return p.hash }

var (
	bundleH1 = "sha256:" + strings.Repeat("1", 64)
	bundleH2 = "sha256:" + strings.Repeat("2", 64)
)

func signUnder(t *testing.T, name, id, payloadHash, bundleHash string) approval.SignedEscalation {
	t.Helper()
	s, err := approval.SignEscalation(approverPrivs[name], approval.EscalationObject{
		EscalationID: id, PayloadHash: payloadHash, PolicyBundleHash: bundleHash, Decision: approval.Approve, Expiry: rigNow.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// policyRig is a 2-of-N escalation "r1" pending under bundleH1, with an
// exec that counts executions and a signer that counts tokens.
type policyRig struct {
	r      *rig
	pend   *fakePending
	pol    *bundlePolicy
	signer *recordSigner
	execs  int
	ph     string
}

func newPolicyRig(t *testing.T) *policyRig {
	p := &policyRig{r: newRig(), pend: newFakePending(), pol: &bundlePolicy{hash: bundleH1}, signer: &recordSigner{}, ph: escFixturePayloadHash(t, "r1")}
	p.pend.m["r1"] = PendingEscalation{Request: setID(fixtureRequest(t, "action_request.evm_tx.json"), "r1"),
		Reasons: []string{"taint-unknown-destination"}, IssuedAt: rigNow, State: model.EscalationPending}
	p.r.cfg.Policy, p.r.cfg.Signer = p.pol, p.signer
	p.r.withPending(p.pend)
	p.r.cfg.Approvers, p.r.cfg.ApprovalQuorum = approverKeySet, 2
	return p
}

func (p *policyRig) approve(e *Engine, s approval.SignedEscalation) (model.Decision, error) {
	return e.ApproveWith(context.Background(), "r1", s, func(_ context.Context, d model.Decision, _ model.ActionRequest, _ auth.Identity) model.Decision {
		p.execs++
		d.SignedTx = "0xsigned"
		return d
	})
}

func (p *policyRig) votes() []approval.Vote { return p.pend.m["r1"].Votes }

// lastBody is the most recent audit body, and lastCode its decision's first reason code.
func (p *policyRig) lastBody() map[string]any { return p.r.audit.bodies[len(p.r.audit.bodies)-1] }
func (p *policyRig) lastCode() string {
	d, _ := p.lastBody()["decision"].(model.Decision)
	if len(d.Reasons) == 0 {
		return ""
	}
	return d.Reasons[0].Code
}

func isPolicyChangedRefusal(d model.Decision, err error) bool {
	return err == nil && d.Outcome == model.Deny && len(d.Reasons) == 1 && d.Reasons[0].Code == "APPROVAL_SIG_POLICY_CHANGED" && d.Token == ""
}

// TestApprovalPolicyBinding: an escalation vote is bound to the policy
// bundle it was signed against (spec/approval-signature-v1.md §2, v2;
// ADR 0010). A policy change while an escalation is pending invalidates the
// votes already cast, refuses envelopes signed under the old bundle, and
// never executes anything twice.
func TestApprovalPolicyBinding(t *testing.T) {
	t.Run("a policy change invalidates recorded votes; approvers re-sign under the new bundle", func(t *testing.T) {
		p := newPolicyRig(t)
		e := p.r.engine(t)
		old := signUnder(t, "ak_ops", "r1", p.ph, bundleH1)
		if d, err := p.approve(e, old); err != nil || d.Outcome == model.Allow || len(p.votes()) != 1 {
			t.Fatalf("first of two votes: %+v, %v, votes %d", d, err, len(p.votes()))
		}

		p.pol.hash = bundleH2 // the policy changes while the escalation is pending
		if got := e.PolicyBundleHash(); got != bundleH2 {
			t.Fatalf("PolicyBundleHash = %s, want the new bundle", got)
		}
		d, err := p.approve(e, signUnder(t, "ops@example.com", "r1", p.ph, bundleH2))
		if err != nil || d.Outcome == model.Allow || p.pend.state("r1") != model.EscalationPending || p.execs != 0 {
			t.Fatalf("the new-bundle vote reached quorum with a vote cast under the old bundle: %+v, %v", d, err)
		}
		if v := p.votes(); len(v) != 1 || v[0].Kid != approverKid(t, "ops@example.com") || v[0].PolicyBundleHash != bundleH2 {
			t.Fatalf("stored votes = %+v, want only the new-bundle vote", v)
		}
		body := p.lastBody()
		inv, _ := body["invalidated_votes"].([]approval.Vote)
		if body["event"] != "vote" || len(inv) != 1 || inv[0].Kid != approverKid(t, "ak_ops") || inv[0].PolicyBundleHash != bundleH1 {
			t.Fatalf("the discarded vote is not audited with the write that drops it: %+v", body)
		}

		if d, err := p.approve(e, old); !isPolicyChangedRefusal(d, err) {
			t.Fatalf("old-bundle resubmission: %+v, %v; want deny APPROVAL_SIG_POLICY_CHANGED", d, err)
		}
		if p.lastCode() != "APPROVAL_SIG_POLICY_CHANGED" || len(p.votes()) != 1 {
			t.Fatalf("refusal not audited, or it changed the votes: %q, %d votes", p.lastCode(), len(p.votes()))
		}

		d, err = p.approve(e, signUnder(t, "ak_ops", "r1", p.ph, bundleH2))
		if err != nil || d.Outcome != model.Allow || d.Token == "" || len(d.Approvals) != 2 || d.PolicyBundleHash != bundleH2 ||
			p.pend.state("r1") != model.EscalationAllowed || p.execs != 1 {
			t.Fatalf("two fresh votes under the new bundle: %+v, %v, execs %d", d, err, p.execs)
		}
	})

	t.Run("the same envelope twice executes once, before and after quorum", func(t *testing.T) {
		p := newPolicyRig(t)
		e := p.r.engine(t)
		a := signUnder(t, "ak_ops", "r1", p.ph, bundleH1)
		b := signUnder(t, "ops@example.com", "r1", p.ph, bundleH1)
		if _, err := p.approve(e, a); err != nil {
			t.Fatal(err)
		}
		if _, err := p.approve(e, a); !errors.Is(err, approval.ErrDuplicateVote) || len(p.votes()) != 1 {
			t.Fatalf("replay before quorum: err = %v, votes %d; want ErrDuplicateVote and one vote", err, len(p.votes()))
		}
		d, err := p.approve(e, b)
		if err != nil || d.Outcome != model.Allow || p.execs != 1 || len(p.signer.ids) != 1 {
			t.Fatalf("quorum: %+v, %v, execs %d tokens %d", d, err, p.execs, len(p.signer.ids))
		}
		for _, s := range []approval.SignedEscalation{b, a} {
			if _, err := p.approve(e, s); !errors.Is(err, model.ErrResolved) {
				t.Fatalf("replay after quorum: err = %v, want ErrResolved", err)
			}
		}
		if p.execs != 1 || len(p.signer.ids) != 1 || len(p.r.limiter.reserved) != 1 {
			t.Fatalf("a replay executed again: execs %d, tokens %d, reservations %d", p.execs, len(p.signer.ids), len(p.r.limiter.reserved))
		}
	})

	t.Run("a valid envelope retried after a policy change is refused and changes no state", func(t *testing.T) {
		p := newPolicyRig(t)
		e := p.r.engine(t)
		a := signUnder(t, "ak_ops", "r1", p.ph, bundleH1)
		if _, err := p.approve(e, a); err != nil {
			t.Fatal(err)
		}
		before := p.pend.m["r1"]
		p.pol.hash = bundleH2
		if d, err := p.approve(e, a); !isPolicyChangedRefusal(d, err) {
			t.Fatalf("retry: %+v, %v; want deny APPROVAL_SIG_POLICY_CHANGED", d, err)
		}
		if !reflect.DeepEqual(p.pend.m["r1"], before) || p.execs != 0 || len(p.signer.ids) != 0 {
			t.Fatalf("the refused retry changed state: %+v", p.pend.m["r1"])
		}
		if p.lastCode() != "APPROVAL_SIG_POLICY_CHANGED" {
			t.Fatalf("refusal not audited: %q", p.lastCode())
		}
	})

	t.Run("after a restart on a new bundle, stored votes are compared with the loaded bundle", func(t *testing.T) {
		p := newPolicyRig(t)
		if _, err := p.approve(p.r.engine(t), signUnder(t, "ak_ops", "r1", p.ph, bundleH1)); err != nil {
			t.Fatal(err)
		}
		// Restart: the record round-trips through its stored form, and a new
		// engine loads a different bundle.
		raw, err := json.Marshal(p.pend.m["r1"])
		if err != nil {
			t.Fatal(err)
		}
		var stored PendingEscalation
		if err := json.Unmarshal(raw, &stored); err != nil || stored.Votes[0].PolicyBundleHash != bundleH1 {
			t.Fatalf("the vote's bundle hash does not survive the state file: %+v, %v", stored.Votes, err)
		}
		p.pend.m["r1"] = stored
		p.pol = &bundlePolicy{hash: bundleH2}
		p.r.cfg.Policy = p.pol
		e := p.r.engine(t)

		d, err := p.approve(e, signUnder(t, "ops@example.com", "r1", p.ph, bundleH2))
		if err != nil || d.Outcome == model.Allow || p.execs != 0 || len(p.votes()) != 1 {
			t.Fatalf("a pre-restart vote counted under the new bundle: %+v, %v, votes %d", d, err, len(p.votes()))
		}
		if d, err := p.approve(e, signUnder(t, "ak_ops", "r1", p.ph, bundleH2)); err != nil || d.Outcome != model.Allow || p.execs != 1 {
			t.Fatalf("re-signed after restart: %+v, %v", d, err)
		}
	})

	t.Run("a pre-v2 stored vote (no bundle hash) never counts", func(t *testing.T) {
		p := newPolicyRig(t)
		pe := p.pend.m["r1"]
		pe.Votes = []approval.Vote{{Kid: approverKid(t, "ak_ops"), Owner: approval.Owner{KeyID: "ak_ops"}, Decision: approval.Approve, Expiry: rigNow.Add(time.Minute)}}
		p.pend.m["r1"] = pe
		d, err := p.approve(p.r.engine(t), signUnder(t, "ops@example.com", "r1", p.ph, bundleH1))
		if err != nil || d.Outcome == model.Allow || len(p.votes()) != 1 || p.lastBody()["invalidated_votes"] == nil {
			t.Fatalf("a vote with no bundle binding counted: %+v, %v", d, err)
		}
	})
}
