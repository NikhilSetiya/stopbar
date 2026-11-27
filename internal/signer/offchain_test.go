package signer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// The EIP-712 specification's own example, with its published digest.
const mailTD = `{"types":{
  "EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
  "Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],
  "Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},
 "primaryType":"Mail",
 "domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
 "message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}`

const mailDigest = "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"

func typedAct(t *testing.T, td string, chain uint64) model.Action {
	t.Helper()
	var d model.TypedData
	if err := json.Unmarshal([]byte(td), &d); err != nil {
		t.Fatal(err)
	}
	a := model.Action{Kind: model.KindEVMTypedData, ChainID: &chain, From: anvilAddr, TypedData: &d}
	r := request(a)
	r.IssuedAt, r.TTLSeconds, r.Provenance.Labels = time.Unix(1, 0), 60, []string{} // only the action is under test
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return a
}

func recovered(t *testing.T, digest common.Hash, sig []byte) string {
	t.Helper()
	if len(sig) != 65 || sig[64] < 27 {
		t.Fatalf("signature %x: want 65 bytes with v = 27/28", sig)
	}
	s := append([]byte{}, sig...)
	s[64] -= 27
	pub, err := crypto.SigToPub(digest[:], s)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(crypto.PubkeyToAddress(*pub).Hex())
}

func TestSignTypedDataMatchesEIP712Vector(t *testing.T) {
	r := newRig(t)
	a := typedAct(t, mailTD, 1)
	sig, digest, err := r.adapter.SignMessage(context.Background(), r.token(t, a, model.Allow), a, who)
	if err != nil {
		t.Fatal(err)
	}
	if digest.Hex() != mailDigest {
		t.Fatalf("digest %s, want the EIP-712 spec's %s", digest.Hex(), mailDigest)
	}
	if got := recovered(t, digest, sig); got != anvilAddr {
		t.Fatalf("signature recovers %s, want %s", got, anvilAddr)
	}
}

func TestSignPersonalMessage(t *testing.T) {
	r := newRig(t)
	chain := uint64(8453)
	a := model.Action{Kind: model.KindEVMPersonalSign, ChainID: &chain, From: anvilAddr, Message: "0x68656c6c6f"}
	sig, digest, err := r.adapter.SignMessage(context.Background(), r.token(t, a, model.Allow), a, who)
	if err != nil {
		t.Fatal(err)
	}
	if digest != common.BytesToHash(accounts.TextHash([]byte("hello"))) || recovered(t, digest, sig) != anvilAddr {
		t.Fatalf("digest %s / signer mismatch", digest.Hex())
	}
}

// Change the typed data after the decision and nothing is signed: the core
// recomputes payload_hash from the exact payload about to be signed.
func TestTypedDataSwapIsRefused(t *testing.T) {
	r := newRig(t)
	a := typedAct(t, mailTD, 1)
	tok := r.token(t, a, model.Allow)
	b := typedAct(t, strings.Replace(mailTD, "Hello, Bob!", "Send everything", 1), 1)
	if _, _, err := r.adapter.SignMessage(context.Background(), tok, b, who); code(err) != "PAYLOAD_MISMATCH" {
		t.Fatalf("swapped message: %v", err)
	}
	// The token was not spent by the failed attempt.
	if _, _, err := r.adapter.SignMessage(context.Background(), tok, a, who); err != nil {
		t.Fatalf("original after a failed swap: %v", err)
	}
	// Kinds don't cross: a typed-data allow can't drive SignTx, nor a tx allow SignMessage.
	if _, _, err := r.adapter.SignTx(context.Background(), r.token(t, a, model.Allow), a, who); !errors.Is(err, ErrNotBindable) {
		t.Fatalf("SignTx on typed data: %v", err)
	}
	if _, _, err := r.adapter.SignMessage(context.Background(), r.token(t, action(), model.Allow), action(), who); !errors.Is(err, ErrNotBindable) {
		t.Fatalf("SignMessage on a tx: %v", err)
	}
	if _, _, err := r.adapter.SignMessage(context.Background(), r.token(t, a, model.Deny), a, who); code(err) != "NOT_ALLOWED" {
		t.Fatalf("deny token: %v", err)
	}
}

// The digest is derived only from the bound action; a domain whose chainId
// is not the action's chain is refused even if validation were skipped.
func TestMessageDigestRefusesChainMismatch(t *testing.T) {
	a := typedAct(t, mailTD, 1)
	other := uint64(8453)
	a.ChainID = &other
	if _, err := MessageDigest(a); !errors.Is(err, ErrNotBindable) {
		t.Fatalf("chain mismatch: %v", err)
	}
}

func TestGatekeeperSignsOffchain(t *testing.T) {
	r := newRig(t)
	e := &fakeEngine{r: r, outcome: model.Allow}
	g := &Gatekeeper{Engine: e, Adapter: r.adapter}
	ctx := auth.WithIdentity(context.Background(), who)
	d, _ := g.Evaluate(ctx, request(typedAct(t, mailTD, 1)))
	if d.Outcome != model.Allow || d.SigningHash != mailDigest || d.SignedTx != "" || d.Validate() != nil || len(e.commits) != 1 || !strings.HasSuffix(e.commits[0], mailDigest) {
		t.Fatalf("allow: %+v commits=%v", d, e.commits)
	}
	sig, _ := hexutil.Decode(d.Signature)
	if recovered(t, common.HexToHash(d.SigningHash), sig) != anvilAddr {
		t.Fatal("signature does not recover the wallet")
	}
}
