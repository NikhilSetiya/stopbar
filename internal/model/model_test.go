package model

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/setiyanikhil/stopbar/internal/canon"
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

func TestDecisionFixture(t *testing.T) {
	d := roundTrip[Decision](t, "../../spec/fixtures/decision.deny.json")
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func validEVM() ActionRequest {
	chain := uint64(8453)
	return ActionRequest{
		ID: "req_1", Tenant: "t", Nonce: "0123456789abcdef", IssuedAt: time.Now(), TTLSeconds: 60,
		Actor: Actor{AgentID: "a"},
		Action: Action{Kind: KindEVMTx, ChainID: &chain, ValueWei: "0",
			From: "0x2222222222222222222222222222222222222222", To: "0x3333333333333333333333333333333333333333"},
		Provenance: Provenance{Labels: []string{}},
	}
}

func TestActionRequestValidate(t *testing.T) {
	cases := map[string]struct {
		mut  func(*ActionRequest)
		want string
	}{
		"ok":            {func(*ActionRequest) {}, ""},
		"ttl too long":  {func(r *ActionRequest) { r.TTLSeconds = 301 }, "ttl_seconds"},
		"ttl zero":      {func(r *ActionRequest) { r.TTLSeconds = 0 }, "ttl_seconds"},
		"short nonce":   {func(r *ActionRequest) { r.Nonce = "x" }, "nonce"},
		"bad to":        {func(r *ActionRequest) { r.Action.To = "0x123" }, "action.to"},
		"float wei":     {func(r *ActionRequest) { r.Action.ValueWei = "1.5" }, "value_wei"},
		"negative wei":  {func(r *ActionRequest) { r.Action.ValueWei = "-1" }, "value_wei"},
		"leading zero":  {func(r *ActionRequest) { r.Action.ValueWei = "01" }, "value_wei"},
		"wei > uint256": {func(r *ActionRequest) { r.Action.ValueWei = "1" + strings.Repeat("0", 78) }, "uint256"},
		"odd data":      {func(r *ActionRequest) { r.Action.Data = "0xabc" }, "action.data"},
		"no chain":      {func(r *ActionRequest) { r.Action.ChainID = nil }, "chain_id"},
		"nil labels":    {func(r *ActionRequest) { r.Provenance.Labels = nil }, "provenance.labels"},
		"bad kind":      {func(r *ActionRequest) { r.Action.Kind = "transfer" }, "action.kind"},
		"tool missing":  {func(r *ActionRequest) { r.Action = Action{Kind: KindToolCall} }, "action.tool"},
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
	base := Decision{RequestID: "r", Outcome: Allow, PolicyBundleHash: "sha256:x", PayloadHash: "keccak256:y", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
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
