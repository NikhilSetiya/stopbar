package signer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/nonce"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// An off-chain signature spends its token inside the evaluation's state unit
// (CS-197), exactly as SignTx does: the spent token is on disk only once the
// unit commits, and the token is refused again within the same unit.
func TestSignMessageSpendsInTheUnit(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	spent, err := nonce.Open(db, "adapter_spent_v1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t)
	wk, _ := crypto.HexToECDSA(anvilKey)
	v := &decision.Verifier{Keys: r.ring.PublicKeys, Iss: "stopbar:test", Aud: "signer:local-1", Tenant: "acme",
		Spent: spent, Clock: func() time.Time { return r.now }}
	ad, err := New(v, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ad.keys[crypto.PubkeyToAddress(wk.PublicKey)] = wk

	a := typedAct(t, mailTD, 1)
	tok := r.token(t, a, model.Allow)
	u := db.NewUnit()
	ctx := store.WithUnit(context.Background(), u)
	if _, _, err := ad.SignMessage(ctx, tok, a, who); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ad.SignMessage(ctx, tok, a, who); code(err) != "REPLAYED" {
		t.Fatalf("second use in the same unit: %v, want REPLAYED", err)
	}
	onDisk := func() int {
		s, err := nonce.Open(db, "adapter_spent_v1", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s.Len()
	}
	if n := onDisk(); n != 0 {
		t.Fatalf("%d spent tokens on disk before the unit commits", n)
	}
	if err := u.Commit(); err != nil {
		t.Fatal(err)
	}
	if n := onDisk(); n != 1 {
		t.Fatalf("%d spent tokens on disk after commit, want 1", n)
	}
}
