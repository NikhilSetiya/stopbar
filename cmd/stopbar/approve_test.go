package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestApproveCmdArgOrder guards the CLI's `approve <id> --url ... --key ...`
// form: the id comes before the flags, and Go's flag package stops at the first
// positional, so approveCmd must pull the id out before parsing (regression:
// the id-first form once exited 2 with a usage error, which the demo swallowed
// as a refusal).
func TestApproveCmdArgOrder(t *testing.T) {
	var gotPath, gotAuth, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotMethod = r.URL.Path, r.Header.Get("Authorization"), r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"request_id":"req_abc","outcome":"allow"}`))
	}))
	defer srv.Close()

	// id first, then flags — the shape demo-live uses.
	if err := approveCmd([]string{"req_abc", "--url", srv.URL, "--key", "stopbar_sk_test"}); err != nil {
		t.Fatalf("approveCmd(id-first): %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/approvals/req_abc" {
		t.Fatalf("method/path = %s %s, want POST /v1/approvals/req_abc", gotMethod, gotPath)
	}
	if gotAuth != "Bearer stopbar_sk_test" {
		t.Fatalf("Authorization = %q, want bearer token", gotAuth)
	}
}

func TestApproveCmdRejectsMissingID(t *testing.T) {
	for _, args := range [][]string{{}, {"--url", "http://x", "--key", "k"}} {
		if err := approveCmd(args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Fatalf("approveCmd(%v) err = %v, want a usage error", args, err)
		}
	}
}

// TestRejectCmd: `reject <id> --url ... --key ...` (id first, like approve)
// posts to /v1/approvals/<id>/reject, and only a 403 APPROVAL_REJECTED deny
// counts as success; a self-rejection refusal or an unknown id is an error.
func TestRejectCmd(t *testing.T) {
	var gotPath, gotAuth string
	status, body := http.StatusForbidden, `{"request_id":"req_abc","outcome":"deny","reasons":[{"code":"APPROVAL_REJECTED"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	if err := rejectCmd([]string{"req_abc", "--url", srv.URL, "--key", "stopbar_sk_ops"}); err != nil {
		t.Fatalf("rejectCmd: %v", err)
	}
	if gotPath != "/v1/approvals/req_abc/reject" || gotAuth != "Bearer stopbar_sk_ops" {
		t.Fatalf("path/auth = %s %q", gotPath, gotAuth)
	}
	for _, c := range []struct {
		status int
		body   string
	}{
		{http.StatusForbidden, `{"outcome":"deny","reasons":[{"code":"APPROVAL_SELF_APPROVAL"}]}`},
		{http.StatusNotFound, `{"code":"NOT_FOUND"}`},
		{http.StatusConflict, `{"code":"ALREADY_RESOLVED"}`},
	} {
		status, body = c.status, c.body
		if err := rejectCmd([]string{"req_abc", "--url", srv.URL}); err == nil {
			t.Fatalf("rejectCmd accepted HTTP %d %s", c.status, c.body)
		}
	}
	if err := rejectCmd([]string{"--url", srv.URL, "req_abc"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("flags-first form: err = %v, want usage", err)
	}
}
