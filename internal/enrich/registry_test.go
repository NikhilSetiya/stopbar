package enrich

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

const (
	payee    = "0x7a25a1c4e3b2d1f09876543210fedcba98760c21"
	poisoned = "0x7a25ffffffffffffffffffffffffffffffff0c21" // same first and last 4 hex digits
	self     = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
)

var (
	t0        = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	requester = auth.Identity{Method: auth.MethodAPIKey, Tenant: "acme", AgentID: "ops-bot", KeyID: "ak_req"}
	approver  = auth.Identity{Method: auth.MethodAPIKey, Tenant: "acme", AgentID: "alice", KeyID: "ak_alice"}

	// Approver keys (CS-151): alice and bob are distinct owners; alice2 is a
	// second key of alice's; reqKey is bound to the requester's API key.
	alicePriv, alice2Priv, bobPriv, reqPriv = testKey("alice"), testKey("alice2"), testKey("bob"), testKey("requester")
)

func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("registry test approver " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func approverKeys(t *testing.T) *approval.KeySet {
	t.Helper()
	k := func(id string, priv ed25519.PrivateKey, o approval.Owner) approval.Key {
		return approval.Key{ID: id, Tenant: "acme", Owner: o, Public: priv.Public().(ed25519.PublicKey)}
	}
	ks, err := approval.NewKeySet([]approval.Key{
		k("alice", alicePriv, approval.Owner{AgentID: "alice"}), k("alice2", alice2Priv, approval.Owner{AgentID: "alice"}),
		k("bob", bobPriv, approval.Owner{AgentID: "bob"}), k("req", reqPriv, approval.Owner{KeyID: "ak_req"})})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// sign signs an approval of c with priv, valid for 30 minutes from now; f
// may alter the object first.
func sign(t *testing.T, priv ed25519.PrivateKey, c model.Contact, now time.Time, f func(*approval.ContactObject)) approval.SignedContact {
	t.Helper()
	o := approval.ContactObject{Tenant: c.Tenant, ContactID: c.ID, Address: c.Address, Decision: approval.Approve, Expiry: now.Add(30 * time.Minute).Unix()}
	if f != nil {
		f(&o)
	}
	s, err := approval.SignContact(priv, o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// approve2 reaches the 2-of-N quorum on c with alice's and bob's keys.
func approve2(t *testing.T, r *Registry, c model.Contact, now time.Time) model.Contact {
	t.Helper()
	if _, err := r.Approve(c.Tenant, c.ID, sign(t, alicePriv, c, now, nil), approver, now); err != nil {
		t.Fatal(err)
	}
	a, err := r.Approve(c.Tenant, c.ID, sign(t, bobPriv, c, now, nil), approver, now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// newRegistry returns a registry with a 24h cooling-off whose clock the test
// moves through *now.
func newRegistry(t *testing.T) (*Registry, *store.DB, *time.Time) {
	t.Helper()
	db, err := store.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lg, err := audit.New(audit.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	r, err := OpenRegistry(db, lg)
	if err != nil {
		t.Fatal(err)
	}
	now := t0
	r.Clock = func() time.Time { return now }
	r.Approvers, r.Quorum = approverKeys(t), 2
	return r, db, &now
}

// facts runs the enricher for a payment from self to dest.
func facts(t *testing.T, r *Registry, tenant, dest string) (known, similar bool) {
	t.Helper()
	er := &model.EnrichedRequest{
		Request: model.ActionRequest{Tenant: tenant, Action: model.Action{Kind: model.KindEVMTx, From: self}},
		Intent:  model.IntentSummary{Destination: dest, Flags: []string{}},
	}
	if err := r.Enrich(context.Background(), er); err != nil {
		t.Fatal(err)
	}
	return er.Destination.Known, er.Destination.SimilarToKnown
}

func TestSimilar(t *testing.T) {
	for _, tt := range []struct {
		name string
		b    string
		want bool
	}{
		{"same address is not similar (it is known)", payee, false},
		{"first 4 and last 4 match", poisoned, true},
		{"first 8 match", "0x7a25a1c4000000000000000000000000000000ff", true},
		{"last 8 match", "0xff00000000000000000000000000000098760c21", true},
		{"first 4, last 3", "0x7a25ffffffffffffffffffffffffffffffff1c21", false},
		{"first 3, last 4", "0x7a2fffffffffffffffffffffffffffffffff0c21", false},
		{"first 7 only", "0x7a25a1cfffffffffffffffffffffffffffffffff", false},
		{"unrelated", "0x9999999999999999999999999999999999999999", false},
		{"not an address", "0x7a25", false},
	} {
		if got := Similar(payee, tt.b); got != tt.want {
			t.Errorf("%s: Similar(%s, %s) = %v, want %v", tt.name, payee, tt.b, got, tt.want)
		}
	}
}

// The lifecycle (CS-134): a requested addition is unknown while pending and
// while cooling off, known once active_from passes, and gone the moment it is
// removed. Each step is checked against the enricher at the injected clock.
func TestRegistryLifecycle(t *testing.T) {
	r, db, now := newRegistry(t)
	c, err := r.Request("acme", "0x7A25A1C4E3B2D1F09876543210FEDCBA98760C21", "payroll", requester, *now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Address != payee || c.Status != model.ContactPendingApproval || c.RequestedBy != "ak_req" || len(c.SimilarTo) != 0 {
		t.Fatalf("request: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("requested contact invalid: %v", err)
	}

	steps := []struct {
		name    string
		advance time.Duration
		do      func() error
		status  model.ContactStatus
		known   bool
	}{
		{"pending, not approved: unknown", 0, nil, model.ContactPendingApproval, false},
		{"pending for 48h without approval: still unknown", 48 * time.Hour, nil, model.ContactPendingApproval, false},
		{"self-approval refused, still pending", 0, func() error {
			if _, err := r.Approve("acme", c.ID, sign(t, reqPriv, c, *now, nil), requester, *now); !errors.Is(err, model.ErrSelfApproval) {
				t.Fatalf("self-approval: got %v, want ErrSelfApproval", err)
			}
			return nil
		}, model.ContactPendingApproval, false},
		{"another tenant cannot see it", 0, func() error {
			if _, err := r.Approve("other", c.ID, sign(t, alicePriv, c, *now, nil), approver, *now); !errors.Is(err, model.ErrNoContact) {
				t.Fatalf("cross-tenant approve: got %v, want ErrNoContact", err)
			}
			return nil
		}, model.ContactPendingApproval, false},
		{"one of two votes: still pending", 0, func() error {
			a, err := r.Approve("acme", c.ID, sign(t, alicePriv, c, *now, nil), approver, *now)
			if err == nil && (a.Status != model.ContactPendingApproval || len(a.Votes) != 1 || a.Quorum != 2 || a.ApprovedAt != nil) {
				t.Fatalf("first vote: %+v", a)
			}
			return err
		}, model.ContactPendingApproval, false},
		{"a second key of the same owner does not count", 0, func() error {
			if _, err := r.Approve("acme", c.ID, sign(t, alice2Priv, c, *now, nil), approver, *now); !errors.Is(err, model.ErrDuplicateVote) {
				t.Fatalf("same owner: got %v, want ErrDuplicateVote", err)
			}
			return nil
		}, model.ContactPendingApproval, false},
		{"second distinct owner: approved, cooling off, still unknown", 0, func() error {
			a, err := r.Approve("acme", c.ID, sign(t, bobPriv, c, *now, nil), approver, *now)
			if err == nil && (a.ApprovedBy != "alice,bob" || !a.ActiveFrom.Equal(now.Add(DefaultCoolingOff)) || a.Status != model.ContactCoolingOff || a.Votes != nil) {
				t.Fatalf("approve: %+v", a)
			}
			return err
		}, model.ContactCoolingOff, false},
		{"approving twice is a conflict", 0, func() error {
			if _, err := r.Approve("acme", c.ID, sign(t, alicePriv, c, *now, nil), approver, *now); !errors.Is(err, model.ErrContactApproved) {
				t.Fatalf("second approve: got %v", err)
			}
			return nil
		}, model.ContactCoolingOff, false},
		{"one second before active_from: still unknown", DefaultCoolingOff - time.Second, nil, model.ContactCoolingOff, false},
		{"at active_from: known", time.Second, nil, model.ContactActive, true},
		{"removed: unknown at once", 0, func() error {
			_, err := r.Remove("acme", payee, requester, *now)
			return err
		}, "", false},
	}
	for _, s := range steps {
		*now = now.Add(s.advance)
		if s.do != nil {
			if err := s.do(); err != nil {
				t.Fatalf("%s: %v", s.name, err)
			}
		}
		cs, err := r.List("acme", *now)
		if err != nil {
			t.Fatal(err)
		}
		got := model.ContactStatus("")
		if len(cs) == 1 {
			got = cs[0].Status
			if err := cs[0].Validate(); err != nil {
				t.Fatalf("%s: listed contact invalid: %v", s.name, err)
			}
		}
		known, _ := facts(t, r, "acme", payee)
		if got != s.status || known != s.known {
			t.Fatalf("%s: status %q known %v, want %q %v", s.name, got, known, s.status, s.known)
		}
		if k, _ := facts(t, r, "other", payee); k {
			t.Fatalf("%s: another tenant sees it as known", s.name)
		}
	}
	if _, err := r.Remove("acme", payee, requester, *now); !errors.Is(err, model.ErrNoContact) {
		t.Fatalf("second remove: got %v, want ErrNoContact", err)
	}

	// Every change, and only changes, is audited: request, each vote, removal.
	recs, err := audit.Records(db, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	var types []model.AuditRecordType
	for _, rec := range recs {
		types = append(types, rec.Type)
	}
	want := []model.AuditRecordType{model.AuditContactRequest, model.AuditContactApproval, model.AuditContactApproval, model.AuditContactRemoval}
	if !slices.Equal(types, want) {
		t.Fatalf("audit types %v, want %v", types, want)
	}
	if vb := recs[1].Body.(map[string]any); vb["event"] != "vote" || vb["approver"] != "alice" {
		t.Fatalf("vote record: %+v", vb)
	}
	ab := recs[2].Body.(map[string]any)
	if ab["event"] != "approved" || ab["approver"] != "bob" || ab["cooling_off"] != "24h0m0s" || ab["identity"].(map[string]any)["key_id"] != "ak_alice" {
		t.Fatalf("approval record: %+v", ab)
	}
	if _, err := audit.Verify(db, nil, 1, 0); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

// Request-time similarity (CS-134): a requested addition is checked against
// every one of the tenant's entries, active and pending, with the enricher's
// rule; every match (address and label) is in the pending record and its
// audit entry. An exact duplicate is refused, unaudited.
func TestRegistryRequestChecks(t *testing.T) {
	r, db, now := newRegistry(t)
	hex := func(lead, mid, trail string) string {
		return "0x" + lead + strings.Repeat(mid, 40-len(lead)-len(trail)) + trail
	}
	var (
		first   = hex("1111aaaa", "a", "1111") // lowest address: scanned first
		vendor  = payee
		last    = hex("eeee", "c", "cccceeee") // highest address: scanned last
		pending = hex("5555", "e", "5555")     // requested, never approved
	)
	for addr, label := range map[string]string{first: "alpha", vendor: "vendor", last: "omega"} {
		c, err := r.Request("acme", addr, label, requester, *now)
		if err != nil {
			t.Fatal(err)
		}
		approve2(t, r, c, *now)
	}
	if _, err := r.Request("acme", pending, "pend", requester, *now); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(DefaultCoolingOff) // first, vendor, last active; pending still pending
	if _, err := r.Request("other", hex("1111", "b", "1111"), "", requester, *now); err != nil {
		t.Fatal(err)
	}

	sc := func(a, l string) model.SimilarContact { return model.SimilarContact{Address: a, Label: l} }
	for _, tt := range []struct {
		name, addr, label string
		by                auth.Identity
		wantErr           error
		similar           []model.SimilarContact
	}{
		{"look-alike of the first entry", hex("1111", "b", "1111"), "", requester, nil, []model.SimilarContact{sc(first, "alpha")}},
		{"look-alike of the last entry", hex("eeee", "d", "eeee"), "", requester, nil, []model.SimilarContact{sc(last, "omega")}},
		{"look-alike of a pending entry", hex("5555", "0", "5555"), "", requester, nil, []model.SimilarContact{sc(pending, "pend")}},
		{"look-alike of the first and the last: both recorded", hex("1111aaaa", "0", "cccceeee"), "", requester, nil,
			[]model.SimilarContact{sc(first, "alpha"), sc(last, "omega")}},
		{"look-alike of none", hex("9999", "9", "9999"), "", requester, nil, []model.SimilarContact{}},
		{"exact duplicate of an active entry", vendor, "", requester, model.ErrContactExists, nil},
		{"exact duplicate, different case", "0x" + strings.ToUpper(last[2:]), "", requester, model.ErrContactExists, nil},
		{"exact duplicate of a pending entry", pending, "", requester, model.ErrContactExists, nil},
		{"malformed", "0x1234", "", requester, errors.New("any"), nil},
		{"label too long", hex("8888", "8", "8888"), strings.Repeat("x", model.MaxContactLabel+1), requester, errors.New("any"), nil},
		{"no requester key", hex("8888", "8", "8888"), "", auth.Identity{Tenant: "acme"}, errors.New("any"), nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before, _ := audit.Records(db, 1, 0)
			c, err := r.Request("acme", tt.addr, tt.label, tt.by, *now)
			after, _ := audit.Records(db, 1, 0)
			if tt.wantErr != nil {
				if err == nil || (tt.wantErr.Error() != "any" && !errors.Is(err, tt.wantErr)) {
					t.Fatalf("got %v, want %v", err, tt.wantErr)
				}
				if len(after) != len(before) {
					t.Fatal("a refused request was audited")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.SimilarTo, tt.similar) {
				t.Fatalf("similar_to %v, want %v", c.SimilarTo, tt.similar)
			}
			// The audit entry and the listing carry the same matches.
			last := after[len(after)-1]
			body := last.Body.(map[string]any)["contact"].(map[string]any)
			got := body["similar_to"].([]any)
			if last.Type != model.AuditContactRequest || len(got) != len(tt.similar) {
				t.Fatalf("audit record: %+v", last)
			}
			for i, s := range tt.similar {
				if m := got[i].(map[string]any); m["address"] != s.Address || m["label"] != s.Label {
					t.Fatalf("audit similar_to[%d] = %v, want %v", i, m, s)
				}
			}
			cs, _ := r.List("acme", *now)
			i := slices.IndexFunc(cs, func(x model.Contact) bool { return x.ID == c.ID })
			if i < 0 || !slices.Equal(cs[i].SimilarTo, tt.similar) || cs[i].Status != model.ContactPendingApproval {
				t.Fatalf("listing: %+v", cs)
			}
		})
	}
	// The pending look-alike of the first entry stays unknown; a payment to
	// it is flagged similar to the active entry.
	if known, similar := facts(t, r, "acme", hex("1111", "b", "1111")); known || !similar {
		t.Fatalf("pending look-alike: known=%v similar=%v", known, similar)
	}
}

func TestRegistryEnrich(t *testing.T) {
	r, _, now := newRegistry(t)
	if _, err := r.Seed("acme", payee, *now); err != nil {
		t.Fatal(err)
	}
	if added, err := r.Seed("acme", payee, *now); err != nil || added {
		t.Fatalf("re-seed must be a no-op: %v %v", added, err)
	}
	for _, tt := range []struct {
		name, tenant, dest string
		kind               model.ActionKind
		known, similar     bool
		flags              []string
	}{
		{"registered", "acme", payee, model.KindEVMTx, true, false, []string{}},
		{"registered, mixed case", "acme", "0x7A25A1C4E3B2D1F09876543210FEDCBA98760C21", model.KindEVMTx, true, false, []string{}},
		{"poisoned lookalike", "acme", poisoned, model.KindEVMTx, false, true, []string{FlagNewDestination, FlagSimilarDestination}},
		{"new", "acme", "0x9999999999999999999999999999999999999999", model.KindEVMTx, false, false, []string{FlagNewDestination}},
		{"the sending wallet itself", "acme", self, model.KindEVMTx, true, false, []string{}},
		{"another tenant's registry does not count", "other", payee, model.KindEVMTx, false, false, []string{FlagNewDestination}},
		{"no destination", "acme", "", model.KindEVMTx, false, false, []string{}},
		{"tool call", "acme", payee, model.KindToolCall, false, false, []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			er := &model.EnrichedRequest{
				Request: model.ActionRequest{Tenant: tt.tenant, Action: model.Action{Kind: tt.kind, From: self}},
				Intent:  model.IntentSummary{Destination: tt.dest, Flags: []string{}},
			}
			if err := r.Enrich(context.Background(), er); err != nil {
				t.Fatal(err)
			}
			if er.Destination.Known != tt.known || er.Destination.SimilarToKnown != tt.similar || !slices.Equal(er.Intent.Flags, tt.flags) {
				t.Fatalf("got %+v flags %v, want known=%v similar=%v flags %v", er.Destination, er.Intent.Flags, tt.known, tt.similar, tt.flags)
			}
		})
	}
	// A pending or cooling-off look-alike is not a reference for similarity.
	if _, err := r.Request("acme", "0x5555555555555555555555555555555555555555", "", requester, *now); err != nil {
		t.Fatal(err)
	}
	if _, similar := facts(t, r, "acme", "0x5555ffffffffffffffffffffffffffffffff5555"); similar {
		t.Fatal("similarity judged against a pending entry")
	}
	// Enrich never writes into a flag slice it shares with the decoder's intent.
	shared := make([]string, 1, 4)
	shared[0] = "x"
	er := &model.EnrichedRequest{Request: model.ActionRequest{Tenant: "acme", Action: model.Action{Kind: model.KindEVMTx, From: self}},
		Intent: model.IntentSummary{Destination: poisoned, Flags: shared}}
	if err := r.Enrich(context.Background(), er); err != nil {
		t.Fatal(err)
	}
	if shared[:2][1] != "" {
		t.Fatalf("enrich wrote %q into the shared backing array", shared[:2][1])
	}
}

// Signed contact approvals fail closed (CS-151): a signature that fails any
// check counts for nothing and leaves no record; an expired vote stops
// counting; with no approver keys nothing can be approved.
func TestRegistryApproveFailures(t *testing.T) {
	r, db, now := newRegistry(t)
	c, err := r.Request("acme", payee, "", requester, *now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := r.Request("acme", "0x9999999999999999999999999999999999999999", "", requester, *now)
	if err != nil {
		t.Fatal(err)
	}
	outsider := testKey("outsider")
	for _, tt := range []struct {
		name string
		sig  approval.SignedContact
		code string
	}{
		{"signed for another entry", sign(t, alicePriv, other, *now, nil), approval.CodeWrongContact},
		{"address swapped in the object", sign(t, alicePriv, c, *now, func(o *approval.ContactObject) { o.Address = other.Address }), approval.CodeWrongContact},
		{"another tenant's object", sign(t, alicePriv, c, *now, func(o *approval.ContactObject) { o.Tenant = "other" }), approval.CodeWrongTenant},
		{"reject is not a contact decision", sign(t, alicePriv, c, *now, func(o *approval.ContactObject) { o.Decision = approval.Reject }), approval.CodeBadDecision},
		{"expired", sign(t, alicePriv, c, *now, func(o *approval.ContactObject) { o.Expiry = now.Add(-time.Second).Unix() }), approval.CodeExpired},
		{"expiry over an hour ahead", sign(t, alicePriv, c, *now, func(o *approval.ContactObject) { o.Expiry = now.Add(2 * time.Hour).Unix() }), approval.CodeExpiryTooFarAhead},
		{"unconfigured key", sign(t, outsider, c, *now, nil), approval.CodeUnknownKey},
		{"tampered under a valid signature", func() approval.SignedContact {
			s := sign(t, alicePriv, c, *now, nil)
			s.Expiry++
			return s
		}(), approval.CodeBadSignature},
	} {
		_, err := r.Approve("acme", c.ID, tt.sig, approver, *now)
		var ve *approval.VerifyError
		if !errors.As(err, &ve) || ve.Code != tt.code {
			t.Errorf("%s: got %v, want %s", tt.name, err, tt.code)
		}
	}
	// A key bound to the requester's agent id is refused too, not just its key id.
	byAgent, err := r.Request("acme", "0x8888888888888888888888888888888888888888", "",
		auth.Identity{Method: auth.MethodAPIKey, Tenant: "acme", AgentID: "bob", KeyID: "ak_bobs_bot"}, *now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve("acme", byAgent.ID, sign(t, bobPriv, byAgent, *now, nil), approver, *now); !errors.Is(err, model.ErrSelfApproval) {
		t.Fatalf("agent-bound self-approval: got %v", err)
	}
	cs, _ := r.List("acme", *now)
	for _, x := range cs {
		if len(x.Votes) != 0 {
			t.Fatalf("a refused signature left a vote: %+v", x)
		}
	}

	// alice's vote expires before bob signs: still pending; alice again: approved.
	if _, err := r.Approve("acme", c.ID, sign(t, alicePriv, c, *now, nil), approver, *now); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(31 * time.Minute)
	if a, err := r.Approve("acme", c.ID, sign(t, bobPriv, c, *now, nil), approver, *now); err != nil || a.ApprovedAt != nil || len(a.Votes) != 1 {
		t.Fatalf("after alice's vote expired: %+v, %v", a, err)
	}
	if a, err := r.Approve("acme", c.ID, sign(t, alicePriv, c, *now, nil), approver, *now); err != nil || a.ApprovedBy != "bob,alice" {
		t.Fatalf("alice re-signs: %+v, %v", a, err)
	}

	// Only the three accepted votes were audited (plus the three requests).
	recs, err := audit.Records(db, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 6 {
		t.Fatalf("%d audit records, want 6", len(recs))
	}

	r.Approvers = nil
	if _, err := r.Approve("acme", other.ID, sign(t, alicePriv, other, *now, nil), approver, *now); err == nil {
		t.Fatal("approval with no approver keys configured succeeded")
	}
}
