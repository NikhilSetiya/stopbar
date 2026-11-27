package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
)

// testApproverKeyFile writes a fresh approver key file and returns its path.
func testApproverKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approver.key")
	if err := approverCmd([]string{"keygen", path}); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeApprovalServer serves GET /v1/approvals/<id> (the object to sign) and
// POST /v1/approvals/<id>[/reject] (the server's response to the signed
// envelope it receives), recording what it saw.
func fakeApprovalServer(t *testing.T, postStatus int, postBody string) (*httptest.Server, *struct {
	getPath, postPath, getAuth, postAuth, method string
	posted                                       approval.SignedEscalation
}) {
	t.Helper()
	got := &struct {
		getPath, postPath, getAuth, postAuth, method string
		posted                                       approval.SignedEscalation
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			got.getPath, got.getAuth = r.URL.Path, r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(gateway.EscalationToSign{
				EscalationID: "req_abc", PayloadHash: "sha256:" + strings.Repeat("a", 64), PolicyBundleHash: "sha256:" + strings.Repeat("b", 64),
				Tenant: "acme", MaxExpiry: 9999999999,
			})
		case http.MethodPost:
			got.postPath, got.postAuth, got.method = r.URL.Path, r.Header.Get("Authorization"), r.Method
			_ = json.NewDecoder(r.Body).Decode(&got.posted)
			w.WriteHeader(postStatus)
			_, _ = w.Write([]byte(postBody))
		}
	}))
	return srv, got
}

// TestApproveCmdArgOrder guards the CLI's `approve <id> --url ... --key ...`
// form: the id comes before the flags, and Go's flag package stops at the
// first positional, so the command must pull the id out before parsing
// (regression: the id-first form once exited 2 with a usage error, which
// the demo swallowed as a refusal). It also checks the full sign flow: GET
// the object to sign, sign it locally, POST the signed envelope.
func TestApproveCmdArgOrder(t *testing.T) {
	srv, got := fakeApprovalServer(t, http.StatusOK, `{"request_id":"req_abc","outcome":"allow"}`)
	defer srv.Close()
	keyFile := testApproverKeyFile(t)

	// id first, then flags — the shape demo-live uses.
	if err := approveCmd([]string{"req_abc", "--url", srv.URL, "--key", "stopbar_sk_test", "--approver-key", keyFile}); err != nil {
		t.Fatalf("approveCmd(id-first): %v", err)
	}
	if got.method != http.MethodPost || got.postPath != "/v1/approvals/req_abc" || got.getPath != "/v1/approvals/req_abc" {
		t.Fatalf("paths: get=%s post=%s %s, want GET and POST /v1/approvals/req_abc", got.getPath, got.method, got.postPath)
	}
	if got.getAuth != "Bearer stopbar_sk_test" || got.postAuth != "Bearer stopbar_sk_test" {
		t.Fatalf("Authorization: get=%q post=%q, want bearer token on both", got.getAuth, got.postAuth)
	}
	if got.posted.Decision != approval.Approve || got.posted.EscalationID != "req_abc" || got.posted.PayloadHash != "sha256:"+strings.Repeat("a", 64) ||
		got.posted.PolicyBundleHash != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("posted envelope = %+v, want an approve for req_abc with the fetched payload and policy bundle hashes", got.posted)
	}
	if got.posted.Kid == "" || got.posted.Sig == "" {
		t.Fatalf("posted envelope is unsigned: %+v", got.posted)
	}
}

func TestApproveCmdRejectsMissingID(t *testing.T) {
	for _, args := range [][]string{{}, {"--url", "http://x", "--key", "k"}} {
		if err := approveCmd(args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("approveCmd(%v) err = %v, want a usage error", args, err)
		}
	}
}

func TestApproveCmdRequiresApproverKey(t *testing.T) {
	if err := approveCmd([]string{"req_abc", "--url", "http://x"}); err == nil || !strings.Contains(err.Error(), "approver-key") {
		t.Fatalf("approveCmd without --approver-key = %v, want a usage error naming --approver-key", err)
	}
}

// TestRejectCmd: `reject <id> --approver-key FILE --url ... --key ...` (id
// first, like approve) GETs what to sign, signs a reject envelope, and
// posts it to /v1/approvals/<id>/reject; only a 403 APPROVAL_REJECTED deny
// counts as success; an already-resolved or unknown id is an error.
func TestRejectCmd(t *testing.T) {
	status, body := http.StatusForbidden, `{"request_id":"req_abc","outcome":"deny","reasons":[{"code":"APPROVAL_REJECTED"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(gateway.EscalationToSign{EscalationID: "req_abc", PayloadHash: "sha256:" + strings.Repeat("a", 64), Tenant: "acme"})
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	keyFile := testApproverKeyFile(t)

	if err := rejectCmd([]string{"req_abc", "--url", srv.URL, "--key", "stopbar_sk_ops", "--approver-key", keyFile}); err != nil {
		t.Fatalf("rejectCmd: %v", err)
	}
	for _, c := range []struct {
		status int
		body   string
	}{
		{http.StatusForbidden, `{"outcome":"deny","reasons":[{"code":"APPROVAL_SELF_APPROVAL"}]}`},
		{http.StatusNotFound, `{"code":"NOT_FOUND"}`},
		{http.StatusConflict, `{"code":"ALREADY_RESOLVED"}`},
		{http.StatusConflict, `{"code":"DUPLICATE_VOTE"}`},
	} {
		status, body = c.status, c.body
		if err := rejectCmd([]string{"req_abc", "--url", srv.URL, "--approver-key", keyFile}); err == nil {
			t.Fatalf("rejectCmd accepted HTTP %d %s", c.status, c.body)
		}
	}
	if err := rejectCmd([]string{"--url", srv.URL, "req_abc", "--approver-key", keyFile}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("flags-first form: err = %v, want usage", err)
	}
}

func TestApproverKeygen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approver.key")
	if err := approverCmd([]string{"keygen", path}); err != nil {
		t.Fatalf("approver keygen: %v", err)
	}
	priv, err := approval.LoadKeyFile(path) // must load as a real approver key
	if err != nil {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	if err := approverCmd([]string{"keygen", path}); err == nil {
		t.Fatal("approver keygen overwrote an existing key")
	}
	_ = priv
}
