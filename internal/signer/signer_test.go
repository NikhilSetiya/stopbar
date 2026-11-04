package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/nonce"
)

// Anvil test account 0: a public test key, never funded.
const (
	anvilKey  = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	anvilAddr = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
)

var b64 = base64.RawURLEncoding

type rig struct {
	ring    *decision.KeyRing
	signer  *decision.Signer
	adapter *Adapter
	now     time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	_, dk, _ := ed25519.GenerateKey(nil)
	r := &rig{ring: decision.NewKeyRing(dk), now: time.Now()}
	r.signer = &decision.Signer{Keys: r.ring, Iss: "stopbar:test", Aud: "signer:local-1"}
	wk, err := crypto.HexToECDSA(anvilKey)
	if err != nil {
		t.Fatal(err)
	}
	v := &decision.Verifier{Keys: r.ring.PublicKeys, Iss: "stopbar:test", Aud: "signer:local-1", Tenant: "acme",
		Spent: nonce.NewMemory(nil), Clock: func() time.Time { return r.now }}
	if r.adapter, err = New(v, nil); err == nil {
		r.adapter.keys[crypto.PubkeyToAddress(wk.PublicKey)] = wk
	} else {
		t.Fatal(err)
	}
	return r
}

func action() model.Action {
	c, two := uint64(8453), 2
	return model.Action{Kind: model.KindEVMTx, ChainID: &c, From: anvilAddr, To: "0x6666666666666666666666666666666666666666",
		ValueWei: "0", Data: "0xa9059cbb0000000000000000000000004444444444444444444444444444444444444444000000000000000000000000000000000000000000006f065c25cb8bd8b00000",
		TxType: &two, TxNonce: "7", GasLimit: "100000", MaxFeePerGas: "2000000000", MaxPriorityFeePerGas: "1000000000"}
}

func request(a model.Action) model.ActionRequest {
	return model.ActionRequest{ID: "req-1", Tenant: "acme", Nonce: "nonce-000000000001", Actor: model.Actor{AgentID: "agent"}, Action: a}
}

func (r *rig) token(t *testing.T, a model.Action, o model.Outcome) string {
	t.Helper()
	ph, err := decision.PayloadHash(a)
	if err != nil {
		t.Fatal(err)
	}
	d := model.Decision{RequestID: "req-1", Outcome: o, PayloadHash: ph, PolicyBundleHash: "sha256:" + strings.Repeat("a", 64),
		IssuedAt: r.now, ExpiresAt: r.now.Add(time.Minute)}
	tok, err := r.signer.Sign(context.Background(), request(a), d)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func code(err error) string {
	var ve *decision.VerifyError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

func TestSignsExactlyTheApprovedTransaction(t *testing.T) {
	r := newRig(t)
	a := action()
	raw, hash, err := r.adapter.SignTx(context.Background(), r.token(t, a, model.Allow), a)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := DecodeRaw(raw)
	if err != nil || tx.Hash() != hash {
		t.Fatalf("decode: %v", err)
	}
	back, err := ActionOf(tx)
	if err != nil {
		t.Fatal(err)
	}
	if back.From != anvilAddr {
		t.Fatalf("recovered sender %s, want %s", back.From, anvilAddr)
	}
	want, _ := decision.PayloadHash(a)
	if got, _ := decision.PayloadHash(back); got != want {
		t.Fatalf("signed tx %+v differs from the approved action", back)
	}
	if back.TxNonce != "7" || back.GasLimit != "100000" || back.MaxFeePerGas != "2000000000" || back.MaxPriorityFeePerGas != "1000000000" {
		t.Fatalf("adapter changed tx fields: %+v", back)
	}
}

// Swap any field after the decision and nothing is signed.
func TestTxSwapIsRefused(t *testing.T) {
	for name, mut := range map[string]func(*model.Action){
		"to":        func(a *model.Action) { a.To = "0x9f30000000000000000000000000000000000c21" },
		"value":     func(a *model.Action) { a.ValueWei = "1" },
		"calldata":  func(a *model.Action) { a.Data = strings.Replace(a.Data, "4444", "5555", 1) },
		"max fee":   func(a *model.Action) { a.MaxFeePerGas = "5000000000000" },
		"tip":       func(a *model.Action) { a.MaxPriorityFeePerGas = "1500000000" },
		"gas limit": func(a *model.Action) { a.GasLimit = "30000000" },
		"tx nonce":  func(a *model.Action) { a.TxNonce = "8" },
		"chain":     func(a *model.Action) { c := uint64(1); a.ChainID = &c },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			approved := action()
			tok := r.token(t, approved, model.Allow)
			swapped := action()
			mut(&swapped)
			if raw, _, err := r.adapter.SignTx(context.Background(), tok, swapped); code(err) != "PAYLOAD_MISMATCH" || raw != nil {
				t.Fatalf("swapped tx: err=%v raw=%x", err, raw)
			}
		})
	}
}

// One allow token, one signature: also under concurrency.
func TestTokenReplayGivesOneSignature(t *testing.T) {
	r := newRig(t)
	a := action()
	tok := r.token(t, a, model.Allow)
	var signed, replayed atomic.Int64
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := r.adapter.SignTx(context.Background(), tok, a)
			switch {
			case err == nil:
				signed.Add(1)
			case code(err) == "REPLAYED":
				replayed.Add(1)
			default:
				t.Errorf("unexpected %v", err)
			}
		}()
	}
	wg.Wait()
	if signed.Load() != 1 || replayed.Load() != 99 {
		t.Fatalf("signed=%d replayed=%d", signed.Load(), replayed.Load())
	}
}

func resign(t *testing.T, priv ed25519.PrivateKey, hdr map[string]any, payload []byte) string {
	t.Helper()
	h, err := canon.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(payload)
	return in + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(in)))
}

func TestTamperedTokensFailClosed(t *testing.T) {
	r := newRig(t)
	a := action()
	good := r.token(t, a, model.Allow)
	parts := strings.Split(good, ".")
	payload, _ := b64.DecodeString(parts[1])
	kid := r.ring.ActiveKid()
	_, stranger, _ := ed25519.GenerateKey(nil)
	pub := r.ring.PublicKeys()[kid]

	edited := strings.Replace(string(payload), `"aud":"signer:local-1"`, `"aud":"signer:local-2"`, 1)
	hsIn := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, pub)
	mac.Write([]byte(hsIn))
	hs := mustHeader(t, map[string]any{"alg": "HS256", "kid": kid, "typ": decision.TokenType})

	for name, tt := range map[string]struct {
		tok  string
		want string
	}{
		"claim edited under signature": {parts[0] + "." + b64.EncodeToString([]byte(edited)) + "." + parts[2], "BAD_SIGNATURE"},
		"wrong kid (unpinned key)":     {resign(t, stranger, map[string]any{"alg": "EdDSA", "kid": decision.Kid(stranger.Public().(ed25519.PublicKey)), "typ": decision.TokenType}, payload), "UNKNOWN_KEY"},
		"pinned kid, other key":        {resign(t, stranger, map[string]any{"alg": "EdDSA", "kid": kid, "typ": decision.TokenType}, payload), "BAD_SIGNATURE"},
		"alg none":                     {mustHeader(t, map[string]any{"alg": "none", "kid": kid, "typ": decision.TokenType}) + "." + parts[1] + ".", "BAD_HEADER"},
		"alg HS256 with public key":    {hs + "." + parts[1] + "." + b64.EncodeToString(mac.Sum(nil)), "BAD_HEADER"},
		"crit header":                  {resign(t, stranger, map[string]any{"alg": "EdDSA", "crit": []string{"exp"}, "kid": kid, "typ": decision.TokenType}, payload), "BAD_HEADER"},
		"deny token":                   {r.token(t, a, model.Deny), "NOT_ALLOWED"},
	} {
		t.Run(name, func(t *testing.T) {
			if raw, _, err := r.adapter.SignTx(context.Background(), tt.tok, a); code(err) != tt.want || raw != nil {
				t.Fatalf("err = %v, want %s", err, tt.want)
			}
		})
	}
	// Expired: same token after its exp.
	r.now = r.now.Add(time.Minute)
	if _, _, err := r.adapter.SignTx(context.Background(), good, a); code(err) != "EXPIRED" {
		t.Fatalf("expired: %v", err)
	}
}

func mustHeader(t *testing.T, h map[string]any) string {
	t.Helper()
	b, err := canon.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(b)
}

func TestWrongAudienceAndUnheldWallet(t *testing.T) {
	r := newRig(t)
	other := &decision.Signer{Keys: r.ring, Iss: "stopbar:test", Aud: "signer:other"}
	a := action()
	ph, _ := decision.PayloadHash(a)
	tok, err := other.Sign(context.Background(), request(a), model.Decision{RequestID: "req-1", Outcome: model.Allow, PayloadHash: ph,
		PolicyBundleHash: "sha256:" + strings.Repeat("a", 64), IssuedAt: r.now, ExpiresAt: r.now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.adapter.SignTx(context.Background(), tok, a); code(err) != "WRONG_AUDIENCE" {
		t.Fatalf("wrong audience: %v", err)
	}
	unheld := action()
	unheld.From = "0x5555555555555555555555555555555555555555"
	if _, _, err := r.adapter.SignTx(context.Background(), r.token(t, unheld, model.Allow), unheld); !errors.Is(err, ErrNoKey) {
		t.Fatalf("unheld wallet: %v", err)
	}
}

func TestDevWalletGuards(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "wallet")
	if err := WriteDevWallet(good, anvilKey); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadDevWallet(good)
	if err != nil || len(keys) != 1 || strings.ToLower(crypto.PubkeyToAddress(keys[0].PublicKey).Hex()) != anvilAddr {
		t.Fatalf("load: %v", err)
	}
	if err := os.Chmod(good, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDevWallet(good); err == nil {
		t.Fatal("group-readable wallet accepted")
	}
	_, dk, _ := ed25519.GenerateKey(nil)
	dkPath := filepath.Join(dir, "decision.key")
	if err := decision.WriteKeyFile(dkPath, dk); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDevWallet(dkPath); err == nil {
		t.Fatal("decision key file loaded as a wallet")
	}
	if err := os.Chmod(good, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := decision.LoadKeyFile(good); err == nil {
		t.Fatal("wallet file loaded as a decision key")
	}
}

// ---- gatekeeper ----

type fakeEngine struct {
	r                 *rig
	mu                sync.Mutex
	commits, releases []string
	commitErr         error
	outcome           model.Outcome
}

func (f *fakeEngine) Evaluate(ctx context.Context, req model.ActionRequest) (model.Decision, error) {
	ph, _ := decision.PayloadHash(req.Action)
	id := req.ID
	d := model.Decision{RequestID: req.ID, Outcome: f.outcome, PayloadHash: ph, PolicyBundleHash: "sha256:" + strings.Repeat("a", 64),
		Approvals: []model.Approval{}, ReservationID: &id, IssuedAt: f.r.now, ExpiresAt: f.r.now.Add(time.Minute)}
	if f.outcome != model.Allow {
		d.ReservationID, d.Reasons = nil, []model.Reason{{Code: "POLICY", PolicyID: "p", Message: "m"}}
		return d, nil
	}
	tok, err := f.r.signer.Sign(ctx, req, d)
	d.Token = tok
	return d, err
}
func (f *fakeEngine) Commit(_ context.Context, id, txRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits = append(f.commits, id+"@"+txRef)
	return f.commitErr
}
func (f *fakeEngine) Release(_ context.Context, id, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releases = append(f.releases, id+": "+reason)
	return nil
}

func TestGatekeeper(t *testing.T) {
	r := newRig(t)
	e := &fakeEngine{r: r, outcome: model.Allow}
	g := &Gatekeeper{Engine: e, Adapter: r.adapter}

	d, _ := g.Evaluate(context.Background(), request(action()))
	if d.Outcome != model.Allow || d.SignedTx == "" || d.Validate() != nil || len(e.commits) != 1 || !strings.HasSuffix(e.commits[0], d.TxHash) {
		t.Fatalf("allow: %+v commits=%v", d, e.commits)
	}

	unheld := action()
	unheld.From = "0x5555555555555555555555555555555555555555"
	req := request(unheld)
	req.Nonce = "nonce-000000000002"
	d, _ = g.Evaluate(context.Background(), req)
	if d.Outcome != model.Deny || d.SignedTx != "" || d.Validate() != nil || len(e.releases) != 1 || !strings.Contains(e.releases[0], "NO_KEY_FOR_FROM") {
		t.Fatalf("adapter refusal: %+v releases=%v", d, e.releases)
	}
	if last := d.Reasons[len(d.Reasons)-1]; last.Code != CodeAdapter {
		t.Fatalf("reason %+v", last)
	}

	e.commitErr = errors.New("audit down")
	req.Nonce, req.Action = "nonce-000000000003", action()
	req.Action.TxNonce = "8"
	d, _ = g.Evaluate(context.Background(), req)
	if d.Outcome != model.Deny || d.SignedTx != "" || len(e.releases) != 2 {
		t.Fatalf("commit failure must discard the signed tx: %+v", d)
	}

	e.outcome = model.Deny
	req.Nonce = "nonce-000000000004"
	if d, _ = g.Evaluate(context.Background(), req); d.Outcome != model.Deny || d.SignedTx != "" {
		t.Fatalf("deny passthrough: %+v", d)
	}
}
