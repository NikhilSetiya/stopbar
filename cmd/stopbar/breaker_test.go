package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// TestBreakerCmd drives `stopbar breaker` against the real gateway and
// limiter: a tripped breaker refuses a reset with one approver's signature
// (the command fails, the breaker stays open) and closes with two.
func TestBreakerCmd(t *testing.T) {
	db, err := store.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	lg, err := audit.New(audit.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	st, err := limiter.NewBoltStore(db, lg)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := limiter.New(limiter.Config{Store: st, BreakerQuorum: 2,
		Rules: []limiter.Rule{{Scope: limiter.ScopeTenant, Window: "1h", MaxUSD: "10", CircuitBreaker: true}}})
	if err != nil {
		t.Fatal(err)
	}
	usd, zero := "11", "0"
	trip := model.EnrichedRequest{Request: model.ActionRequest{Tenant: "acme", Action: model.Action{Kind: model.KindEVMTx}},
		AmountUSD: &usd, MaxFeeUSD: &zero}
	if err := lim.Reserve(context.Background(), "req_trip", trip, time.Minute, nil); !errors.Is(err, engine.ErrCircuitOpen) {
		t.Fatalf("trip: %v", err)
	}

	var recs []any
	for _, k := range []string{"alice", "bob"} {
		sum := sha256.Sum256([]byte("sk_" + k))
		recs = append(recs, map[string]any{"id": "ak_" + k, "tenant": "acme", "scopes": []string{gateway.ApproveScope}, "sha256": hex.EncodeToString(sum[:])})
	}
	b, _ := json.Marshal(recs)
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := auth.LoadKeyStore(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gateway.New(gateway.Config{Breaker: lim, Authenticator: gateway.BearerAuthenticator{Store: ks}, Audit: lg}))
	defer srv.Close()

	if err := breakerCmd([]string{"status", "--tenant", "acme", "--url", srv.URL, "--key", "sk_alice"}); err != nil {
		t.Fatal(err)
	}
	// Insufficient signatures: refused; the same identity again is refused too.
	err = breakerCmd([]string{"reset", "--tenant", "acme", "--url", srv.URL, "--key", "sk_alice"})
	if err == nil || !strings.Contains(err.Error(), "reset refused: 1 of 2") {
		t.Fatalf("one approver: %v", err)
	}
	err = breakerCmd([]string{"reset", "--tenant", "acme", "--url", srv.URL, "--key", "sk_alice"})
	if err == nil || !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "DUPLICATE_VOTE") {
		t.Fatalf("same approver twice: %v", err)
	}
	if !lim.BreakerStatus("acme").Open {
		t.Fatal("breaker closed on one signature")
	}
	if err := breakerCmd([]string{"reset", "--tenant", "acme", "--url", srv.URL, "--key", "sk_bob"}); err != nil {
		t.Fatalf("second approver: %v", err)
	}
	if lim.BreakerStatus("acme").Open {
		t.Fatal("breaker still open after quorum")
	}
	if err := breakerCmd([]string{"reset", "--tenant", "acme", "--url", srv.URL, "--key", "sk_bob"}); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("reset of a closed breaker: %v", err)
	}
	for _, args := range [][]string{{}, {"status"}, {"reset", "--tenant", "acme"}, {"open", "--tenant", "acme"}} {
		if err := breakerCmd(args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("breakerCmd(%v) = %v, want usage", args, err)
		}
	}
}
