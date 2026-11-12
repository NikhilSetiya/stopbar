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
