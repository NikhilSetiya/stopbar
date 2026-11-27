package model

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/canon"
)

// roundTrip asserts fixture -> struct -> JSON is canonically identical to the fixture,
// i.e. the Go types neither drop nor invent fields.
func roundTrip[T any](t *testing.T, path string) T {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var v T
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canon.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := canon.Transform(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s round-trip mismatch\ngot  %s\nwant %s", path, got, want)
	}
	return v
}

func TestActionRequestFixtures(t *testing.T) {
	files, _ := filepath.Glob("../../spec/fixtures/action_request.*.json")
	if len(files) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			r := roundTrip[ActionRequest](t, f)
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Contact fixtures (CS-134) round-trip and validate, and the served status
// matches what the timestamps say at a time inside the fixture's window.
func TestContactFixtures(t *testing.T) {
	r := roundTrip[ContactRequest](t, "../../spec/fixtures/contact_request.json")
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) // after approval, before active_from
	for _, f := range []string{"contact.pending.json", "contact.cooling_off.json"} {
		t.Run(f, func(t *testing.T) {
			c := roundTrip[Contact](t, "../../spec/fixtures/"+f)
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			if c.StatusAt(at) != c.Status {
				t.Fatalf("status %q, but the timestamps say %q", c.Status, c.StatusAt(at))
			}
		})
	}
}

func TestContactValidate(t *testing.T) {
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	later := at.Add(time.Hour)
	ok := Contact{ID: "ct_1", Tenant: "t", Address: "0x" + strings.Repeat("a", 40), Status: ContactPendingApproval,
		RequestedBy: "ak", RequestedAt: at, SimilarTo: []SimilarContact{}}
	for _, tt := range []struct {
		name string
		mut  func(*Contact)
		want int // problems
	}{
		{"valid pending", func(*Contact) {}, 0},
		{"valid approved", func(c *Contact) {
			c.ApprovedBy, c.ApprovedAt, c.ActiveFrom, c.Status = "ak2", &at, &later, ContactCoolingOff
		}, 0},
		{"everything wrong at once", func(c *Contact) {
			*c = Contact{Address: "0xABC", Label: strings.Repeat("x", MaxContactLabel+1), Status: "live"}
		}, 9},
		{"approval fields half set", func(c *Contact) { c.ApprovedBy = "ak2" }, 1},
		{"active before approval", func(c *Contact) {
			c.ApprovedBy, c.ApprovedAt, c.ActiveFrom, c.Status = "ak2", &later, &at, ContactActive
		}, 1},
		{"unapproved but active", func(c *Contact) { c.Status = ContactActive }, 1},
		{"similar to itself", func(c *Contact) { c.SimilarTo = []SimilarContact{{Address: c.Address}} }, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := ok
			tt.mut(&c)
			err := c.Validate()
			var ve *ValidationError
			switch {
			case tt.want == 0 && err != nil:
				t.Fatalf("unexpected: %v", err)
			case tt.want > 0 && (!errors.As(err, &ve) || len(ve.Problems) != tt.want):
				t.Fatalf("got %v, want %d problems", err, tt.want)
			}
		})
	}
}

func TestDecisionFixture(t *testing.T) {
	for _, f := range []string{"decision.deny.json", "decision.allow_offchain.json"} {
		d := roundTrip[Decision](t, "../../spec/fixtures/"+f)
		if err := d.Validate(); err != nil {
			t.Fatal(f, err)
		}
	}
	// Only an allow may carry an off-chain signature.
	d := roundTrip[Decision](t, "../../spec/fixtures/decision.allow_offchain.json")
	d.Outcome, d.Token, d.Reasons = Deny, "", []Reason{{Code: "POLICY", Message: "m"}}
	if err := d.Validate(); err == nil {
		t.Fatal("deny carrying a signature validated")
	}
}

func TestEscalationStatusFixture(t *testing.T) {
	st := roundTrip[EscalationStatus](t, "../../spec/fixtures/escalation_status.denied.json")
	if err := st.Request.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := st.Decision.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBreakerStatusFixture(t *testing.T) {
	b := roundTrip[BreakerStatus](t, "../../spec/fixtures/breaker_status.open.json")
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBreakerStatusValidate(t *testing.T) {
	at := time.Now()
	open := func() BreakerStatus {
		return BreakerStatus{Tenant: "t", Open: true, TrippedAt: &at, TripRequestID: "req_1", Reason: "cap",
			Votes: []BreakerVote{{Approver: "ak_1", At: at, ExpiresAt: at.Add(BreakerVoteTTL)}}, Quorum: 2}
	}
	cases := map[string]struct {
		mut  func(*BreakerStatus)
		want []string // every problem expected, reported at once
	}{
		"ok open":   {func(*BreakerStatus) {}, nil},
		"ok closed": {func(b *BreakerStatus) { *b = BreakerStatus{Tenant: "t", Votes: []BreakerVote{}, Quorum: 2} }, nil},
		"everything wrong": {func(b *BreakerStatus) {
			b.Tenant, b.Quorum, b.TrippedAt = "", 0, nil
			b.Votes = append(b.Votes, BreakerVote{Approver: "ak_1"}, BreakerVote{})
		}, []string{"tenant", "quorum", "exactly when open", "voted twice", "approver is required", "expires_at must be after at"}},
		"quorum below two": {func(b *BreakerStatus) { b.Quorum = 1 }, []string{"quorum must be at least 2"}},
		"open at quorum": {func(b *BreakerStatus) {
			b.Votes = append(b.Votes, BreakerVote{Approver: "ak_2", At: at, ExpiresAt: at.Add(BreakerVoteTTL)})
		}, []string{"quorum of live reset votes"}},
		"expired votes do not count": {func(b *BreakerStatus) {
			b.ExpiredVotes = []BreakerVote{{Approver: "ak_2", At: at.Add(-2 * time.Hour), ExpiresAt: at.Add(-time.Hour)}}
		}, nil},
		"bad expired vote": {func(b *BreakerStatus) { b.ExpiredVotes = []BreakerVote{{Approver: "ak_2"}} }, []string{"expired_votes[0]"}},
		"closed with votes": {func(b *BreakerStatus) {
			b.Open, b.TrippedAt, b.TripRequestID, b.Reason = false, nil, "", ""
		}, []string{"no reset votes"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := open()
			c.mut(&b)
			err := b.Validate()
			if len(c.want) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("err = %v, want a ValidationError", err)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("missing problem %q in %v", w, err)
				}
			}
		})
	}
}

var txType2 = 2

func validEVM() ActionRequest {
	chain := uint64(8453)
	return ActionRequest{
		ID: "req_1", Tenant: "t", Nonce: "0123456789abcdef", IssuedAt: time.Now(), TTLSeconds: 60,
		Actor: Actor{AgentID: "a"},
		Action: Action{Kind: KindEVMTx, ChainID: &chain, ValueWei: "0",
			From: "0x2222222222222222222222222222222222222222", To: "0x3333333333333333333333333333333333333333",
			TxType: &txType2, TxNonce: "0", GasLimit: "100000", MaxFeePerGas: "2000000000", MaxPriorityFeePerGas: "1000000000"},
		Provenance: Provenance{Labels: []string{}},
	}
}

func TestActionRequestValidate(t *testing.T) {
	cases := map[string]struct {
		mut  func(*ActionRequest)
		want string
	}{
		"ok":              {func(*ActionRequest) {}, ""},
		"ttl too long":    {func(r *ActionRequest) { r.TTLSeconds = 301 }, "ttl_seconds"},
		"ttl zero":        {func(r *ActionRequest) { r.TTLSeconds = 0 }, "ttl_seconds"},
		"short nonce":     {func(r *ActionRequest) { r.Nonce = "x" }, "nonce"},
		"bad to":          {func(r *ActionRequest) { r.Action.To = "0x123" }, "action.to"},
		"float wei":       {func(r *ActionRequest) { r.Action.ValueWei = "1.5" }, "value_wei"},
		"negative wei":    {func(r *ActionRequest) { r.Action.ValueWei = "-1" }, "value_wei"},
		"leading zero":    {func(r *ActionRequest) { r.Action.ValueWei = "01" }, "value_wei"},
		"wei > uint256":   {func(r *ActionRequest) { r.Action.ValueWei = "1" + strings.Repeat("0", 78) }, "uint256"},
		"odd data":        {func(r *ActionRequest) { r.Action.Data = "0xabc" }, "action.data"},
		"no tx type":      {func(r *ActionRequest) { r.Action.TxType = nil }, "tx_type"},
		"legacy tx":       {func(r *ActionRequest) { one := 1; r.Action.TxType = &one }, "tx_type"},
		"eip-7702 type 4": {func(r *ActionRequest) { four := 4; r.Action.TxType = &four }, "tx_type"},
		"no tx nonce":     {func(r *ActionRequest) { r.Action.TxNonce = "" }, "tx_nonce"},
		"no gas limit":    {func(r *ActionRequest) { r.Action.GasLimit = "" }, "gas_limit"},
		"gas < 21000":     {func(r *ActionRequest) { r.Action.GasLimit = "20999" }, "at least 21000"},
		"gas > uint64":    {func(r *ActionRequest) { r.Action.GasLimit = "18446744073709551616" }, "uint64"},
		"tip > max fee":   {func(r *ActionRequest) { r.Action.MaxPriorityFeePerGas = "3000000000" }, "must not exceed"},
		"no max fee":      {func(r *ActionRequest) { r.Action.MaxFeePerGas = "" }, "max_fee_per_gas"},
		"no chain":        {func(r *ActionRequest) { r.Action.ChainID = nil }, "chain_id"},
		"nil labels":      {func(r *ActionRequest) { r.Provenance.Labels = nil }, "provenance.labels"},
		"bad kind":        {func(r *ActionRequest) { r.Action.Kind = "transfer" }, "action.kind"},
		"tool missing":    {func(r *ActionRequest) { r.Action = Action{Kind: KindToolCall} }, "action.tool"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := validEVM()
			c.mut(&r)
			err := r.Validate()
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	err := (ActionRequest{}).Validate()
	var ve *ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) < 5 {
		t.Fatalf("expected many problems, got %v", err)
	}
}

func TestDecisionValidate(t *testing.T) {
	now := time.Now()
	base := Decision{RequestID: "r", Outcome: Allow, PolicyBundleHash: "sha256:" + strings.Repeat("a", 64), PayloadHash: "sha256:" + strings.Repeat("b", 64), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	d := base
	d.Outcome = Deny
	if d.Validate() == nil {
		t.Error("deny without reasons accepted")
	}
	d = base
	d.PayloadHash = ""
	if d.Validate() == nil {
		t.Error("allow without payload binding accepted")
	}
	d = base
	d.PayloadHash = "keccak256:" + strings.Repeat("b", 64)
	if d.Validate() == nil {
		t.Error("non-sha256 payload_hash accepted")
	}
	d = base
	d.Outcome, d.Reasons, d.Token = Deny, []Reason{{PolicyID: "p", Message: "m"}}, "a.b.c"
	if d.Validate() == nil {
		t.Error("deny with a token accepted")
	}
	d = base
	d.Outcome = "maybe"
	if !errors.Is(d.Validate(), ErrInvalidOutcome) {
		t.Error("unknown outcome accepted")
	}
	d = base
	d.ExpiresAt = now
	if d.Validate() == nil {
		t.Error("non-positive validity window accepted")
	}
}

func TestLargeWeiSurvivesJSON(t *testing.T) {
	r := validEVM()
	r.Action.ValueWei = "115792089237316195423570985008687907853269984665640564039457584007913129639935" // 2^256-1
	b, _ := json.Marshal(r)
	var back ActionRequest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Action.ValueWei != r.Action.ValueWei || back.Validate() != nil {
		t.Fatal("uint256 max did not survive")
	}
}
