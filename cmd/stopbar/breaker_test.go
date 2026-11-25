package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// genApproverKeyFile generates a fresh approver key (via the real `stopbar
// approver keygen`), and returns its file path and public key.
func genApproverKeyFile(t *testing.T, name string) (path string, pub ed25519.PublicKey) {
	t.Helper()
	path = filepath.Join(t.TempDir(), name+".key")
	if err := approverCmd([]string{"keygen", path}); err != nil {
		t.Fatal(err)
	}
	priv, err := approval.LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, priv.Public().(ed25519.PublicKey)
}

// TestBreakerCmd drives `stopbar breaker` against the real gateway and
// limiter: a tripped breaker refuses a reset with one approver's signature
// (the command fails, the breaker stays open) and closes with two distinct
// owners (CS-151, replacing #128's API-key vote mechanism).
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

	aliceFile, alicePub := genApproverKeyFile(t, "alice")
	bobFile, bobPub := genApproverKeyFile(t, "bob")
	approvers, err := approval.NewKeySet([]approval.Key{
		{ID: "alice", Tenant: "acme", Owner: approval.Owner{KeyID: "ak_alice"}, Public: alicePub},
		{ID: "bob", Tenant: "acme", Owner: approval.Owner{KeyID: "ak_bob"}, Public: bobPub},
	})
	if err != nil {
		t.Fatal(err)
	}

	lim, err := limiter.New(limiter.Config{Store: st, BreakerQuorum: 2, Approvers: approvers,
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

	srv := httptest.NewServer(gateway.New(gateway.Config{Breaker: lim}))
	defer srv.Close()

	if err := breakerCmd([]string{"status", "--tenant", "acme", "--url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	// Insufficient signatures: refused; the same owner again is refused too.
	err = breakerCmd([]string{"reset", "--tenant", "acme", "--url", srv.URL, "--approver-key", aliceFile})
	if err == nil || !strings.Contains(err.Error(), "reset refused: 1 of 2") {
		t.Fatalf("one approver: %v", err)
	}
	err = breakerCmd([]string{"reset", "--tenant", "acme", "--url", srv.URL, "--approver-key", aliceFile})
	if err == nil || !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), "DUPLICATE_VOTE") {
		t.Fatalf("same approver twice: %v", err)
	}
	if !lim.BreakerStatus("acme").Open {
		t.Fatal("breaker closed on one signature")
	}
	if err := breakerCmd([]string{"reset", "--tenant", "acme", "--url", srv.URL, "--approver-key", bobFile}); err != nil {
		t.Fatalf("second approver: %v", err)
	}
	if lim.BreakerStatus("acme").Open {
		t.Fatal("breaker still open after quorum")
	}
	if err := breakerCmd([]string{"reset", "--tenant", "acme", "--url", srv.URL, "--approver-key", bobFile}); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("reset of a closed breaker: %v", err)
	}
	for _, args := range [][]string{{}, {"status"}, {"reset", "--tenant", "acme"}, {"open", "--tenant", "acme"}} {
		if err := breakerCmd(args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("breakerCmd(%v) = %v, want usage", args, err)
		}
	}
}
