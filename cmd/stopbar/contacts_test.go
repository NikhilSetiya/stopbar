package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/enrich"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// The CLI drives a live gateway + registry over HTTP (CS-134, CS-151): add
// is pending and flags look-alikes, an approver key bound to the requester is
// refused, two distinct approver owners' signatures start the cooling-off,
// remove applies at once, and every change (and the refusal) is audited.
func TestContactsCLIOverAPI(t *testing.T) {
	dir := t.TempDir()
	db, err := store.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lg, err := audit.New(audit.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := enrich.OpenRegistry(db, lg)
	if err != nil {
		t.Fatal(err)
	}
	// Approver keys: ops's is bound to the requester (agent "ops").
	var approvers []approval.Key
	keyFile := map[string]string{}
	for _, owner := range []string{"ops", "alice", "bob"} {
		pub, priv, err := approval.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keyFile[owner] = filepath.Join(dir, owner+".approver")
		if err := approval.WriteKeyFile(keyFile[owner], priv); err != nil {
			t.Fatal(err)
		}
		approvers = append(approvers, approval.Key{ID: owner, Tenant: "acme", Owner: approval.Owner{AgentID: owner}, Public: pub})
	}
	if reg.Approvers, err = approval.NewKeySet(approvers); err != nil {
		t.Fatal(err)
	}
	reg.Quorum = 2
	rec := func(id, scopes, secret string) auth.KeyRecord {
		sum := sha256.Sum256([]byte(secret))
		return auth.KeyRecord{ID: id, Tenant: "acme", AgentID: id, Scopes: strings.Split(scopes, ","), SHA256: hex.EncodeToString(sum[:])}
	}
	keys, _ := json.Marshal([]auth.KeyRecord{rec("ops", "contacts,approve", "sk-ops"), rec("alice", "approve", "sk-alice"), rec("bot", "evaluate", "sk-bot")})
	kf := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(kf, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := auth.LoadKeyStore(kf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gateway.New(gateway.Config{Authenticator: gateway.BearerAuthenticator{Store: ks}, Audit: lg, Contacts: reg}))
	defer srv.Close()

	const payee, lookalike = "0x7a25a1c4e3b2d1f09876543210fedcba98760c21", "0x7a25ffffffffffffffffffffffffffffffff0c21"
	cli := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := runContacts(args, &out)
		return out.String(), err
	}
	out, err := cli("add", payee, "--label", "vendor", "--url", srv.URL, "--key", "sk-ops")
	if err != nil || !strings.Contains(out, "pending_approval") {
		t.Fatalf("add: %v\n%s", err, out)
	}
	cs, _ := reg.List("acme", time.Now())
	id := cs[0].ID

	for _, tt := range []struct {
		name string
		args []string
		want string // substring of the output, or of the error if it starts with "ERR "
	}{
		{"look-alike request warns", []string{"add", lookalike, "--url", srv.URL, "--key", "sk-ops"}, "WARNING: looks like existing entry " + payee + ` "vendor"`},
		{"exact duplicate refused", []string{"add", payee, "--url", srv.URL, "--key", "sk-ops"}, "ERR HTTP 409"},
		{"evaluate-only key cannot request", []string{"add", "0x9999999999999999999999999999999999999999", "--url", srv.URL, "--key", "sk-bot"}, "ERR HTTP 403"},
		{"bad key", []string{"list", "--url", srv.URL, "--key", "nope"}, "ERR HTTP 401"},
		{"approver key bound to the requester refused", []string{"approve", id, "--approver-key", keyFile["ops"], "--url", srv.URL, "--key", "sk-ops"}, "ERR SELF_APPROVAL"},
		{"approver lists, sees pending and the look-alike flag", []string{"list", "--url", srv.URL, "--key", "sk-alice"}, "WARNING: looks like existing entry"},
		{"first signature: vote recorded", []string{"approve", id, "--approver-key", keyFile["alice"], "--url", srv.URL, "--key", "sk-alice"}, "1 of 2 approvers"},
		{"same approver again refused", []string{"approve", id, "--approver-key", keyFile["alice"], "--url", srv.URL, "--key", "sk-alice"}, "ERR DUPLICATE_VOTE"},
		{"approve needs an approver key", []string{"approve", id, "--url", srv.URL, "--key", "sk-alice"}, "ERR usage"},
		{"an approver key file that is not one", []string{"approve", id, "--approver-key", kf, "--url", srv.URL, "--key", "sk-alice"}, "ERR approver key"},
		{"unknown id", []string{"approve", "ct_nope", "--approver-key", keyFile["bob"], "--url", srv.URL, "--key", "sk-alice"}, "ERR HTTP 404"},
		{"second distinct owner: cooling off", []string{"approve", id, "--approver-key", keyFile["bob"], "--url", srv.URL, "--key", "sk-alice"}, "cooling_off"},
		{"approving twice conflicts", []string{"approve", id, "--approver-key", keyFile["bob"], "--url", srv.URL, "--key", "sk-alice"}, "ERR HTTP 409"},
		{"approver key cannot remove", []string{"remove", payee, "--url", srv.URL, "--key", "sk-alice"}, "ERR HTTP 403"},
		{"remove applies at once", []string{"remove", payee, "--url", srv.URL, "--key", "sk-ops"}, "removed " + payee},
		{"removed is gone", []string{"remove", payee, "--url", srv.URL, "--key", "sk-ops"}, "ERR HTTP 404"},
		{"usage", []string{"approve", "--url", srv.URL}, "ERR usage"},
		{"approver key only on approve", []string{"add", "0x9999999999999999999999999999999999999999", "--approver-key", keyFile["bob"], "--url", srv.URL, "--key", "sk-ops"}, "ERR usage"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := cli(tt.args...)
			if want, isErr := strings.CutPrefix(tt.want, "ERR "); isErr {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("got err %v, want one containing %q\n%s", err, want, out)
				}
				return
			}
			if err != nil || !strings.Contains(out, tt.want) {
				t.Fatalf("err %v, output lacks %q:\n%s", err, tt.want, out)
			}
		})
	}

	recs, err := audit.Records(db, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, r := range recs {
		types = append(types, string(r.Type))
	}
	got := strings.Join(types, ",")
	// add, look-alike add, scope reject (bot), self-approval reject, vote,
	// approving vote, scope reject (alice remove), remove.
	want := "contact_request,contact_request,auth_reject,auth_reject,contact_approval,contact_approval,auth_reject,contact_removal"
	if got != want {
		t.Fatalf("audit types\n got %s\nwant %s", got, want)
	}
	if _, err := audit.Verify(db, nil, 1, 0); err != nil {
		t.Fatal(err)
	}
}
