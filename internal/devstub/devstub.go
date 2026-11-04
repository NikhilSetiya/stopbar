// Package devstub provides stand-in engine components so stopbard can run the
// real gateway, engine and policy bundle end to end before the production
// components exist. NOT FOR PRODUCTION: stopbard enables them only with
// -dev-world, logs a warning, and the stub signer issues tokens that every
// conforming verifier rejects (decision-token-v1 §4 step 1).
//
// Each stub names the task that replaces it.
package devstub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// ---- decoder (replaced by CS-141/142) ----

// Decoder decodes the calldata shapes the seed corpus needs: ERC-20
// transfer and approve, and plain native transfers. Anything else is a
// contract_call flagged unknown_call, so the starter policy escalates it.
type Decoder struct{}

const (
	selTransfer = "a9059cbb"
	selApprove  = "095ea7b3"
)

var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

func (Decoder) Supports(a model.Action) bool { return a.Kind == model.KindEVMTx }

func (Decoder) Decode(_ context.Context, a model.Action) (model.IntentSummary, error) {
	data := strings.ToLower(strings.TrimPrefix(a.Data, "0x"))
	to := strings.ToLower(a.To)
	if data == "" {
		return model.IntentSummary{
			Kind: "transfer", Amount: a.ValueWei, Destination: to, Flags: []string{},
			Human: fmt.Sprintf("Send %s wei (native) to %s", a.ValueWei, to),
		}, nil
	}
	if len(data) >= 8 && (data[:8] == selTransfer || data[:8] == selApprove) {
		if len(data) != 8+64+64 {
			return model.IntentSummary{}, fmt.Errorf("devstub: %s calldata has %d hex chars, want 136", data[:8], len(data))
		}
		word1, word2 := data[8:72], data[72:136]
		if strings.Trim(word1[:24], "0") != "" {
			return model.IntentSummary{}, errors.New("devstub: address argument has non-zero high bytes")
		}
		dest := "0x" + word1[24:]
		amt, ok := new(big.Int).SetString(word2, 16)
		if !ok {
			return model.IntentSummary{}, errors.New("devstub: bad amount word")
		}
		asset := &model.Asset{ChainID: *a.ChainID, Address: to}
		if data[:8] == selTransfer {
			return model.IntentSummary{
				Kind: "transfer", Asset: asset, Amount: amt.String(), Destination: dest, Flags: []string{},
				Human: fmt.Sprintf("Transfer %s units of token %s to %s", amt, to, dest),
			}, nil
		}
		flags := []string{}
		if amt.Cmp(maxUint256) == 0 {
			flags = append(flags, "unlimited_approval")
		}
		return model.IntentSummary{
			Kind: "approve", Asset: asset, Amount: amt.String(), Destination: dest, Flags: flags,
			Human: fmt.Sprintf("Approve %s to spend %s units of token %s", dest, amt, to),
		}, nil
	}
	return model.IntentSummary{
		Kind: "contract_call", Destination: to, Flags: []string{"unknown_call"},
		Human: fmt.Sprintf("Call contract %s with undecoded calldata", to),
	}, nil
}

// ---- enricher (replaced by CS-131/132/133) ----

// World is a static view of prices, balances and known destinations, in the
// shape of a corpus entry's `setup` (corpus/schema.json). Velocity comes from
// the real limiter, which is configured from Limits.
type World struct {
	KnownDestinations []string          `json:"known_destinations"`
	Balances          map[string]string `json:"balances"`   // symbol -> whole tokens
	PricesUSD         map[string]string `json:"prices_usd"` // symbol -> USD
	Tokens            map[string]Token  `json:"tokens"`     // contract address -> token
	PriceStale        bool              `json:"price_stale"`
	Limits            []limiter.Rule    `json:"limits"` // empty: DefaultLimits
	// PriorOutflowUSD1h is rejected: prior spend must be real reservations
	// (a corpus `requests` sequence), not a number the enricher invents.
	PriorOutflowUSD1h string `json:"prior_outflow_usd_1h"`
}

// DefaultLimits are LLD §17's example caps, used when a world sets none.
var DefaultLimits = []limiter.Rule{
	{Scope: limiter.ScopeWallet, Window: "1h", MaxUSD: "5000", MaxCount: 50},
	{Scope: limiter.ScopeTenant, Window: "1h", MaxUSD: "20000"},
}

// Token describes an ERC-20 contract. The native asset is symbol "ETH", 18 decimals.
type Token struct {
	Symbol   string `json:"symbol"`
	Decimals int    `json:"decimals"`
}

// LoadWorld reads a World from a JSON file.
func LoadWorld(path string) (*World, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w World
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("devstub: world %s: %w", path, err)
	}
	if w.PriorOutflowUSD1h != "" {
		return nil, fmt.Errorf("devstub: world %s: prior_outflow_usd_1h is not supported; model prior spend as a `requests` sequence", path)
	}
	if len(w.Limits) == 0 {
		w.Limits = DefaultLimits
	}
	return &w, nil
}

// Enrich fills amount, balance share and destination facts. A
// missing price or balance is left unset (and the price marked stale), so the
// policy layer fails closed rather than evaluating a guess.
func (w *World) Enrich(_ context.Context, er *model.EnrichedRequest) error {
	symbol, decimals := "ETH", 18
	if er.Intent.Asset != nil {
		t, ok := w.Tokens[strings.ToLower(er.Intent.Asset.Address)]
		if !ok {
			return fmt.Errorf("devstub: unknown token %s", er.Intent.Asset.Address)
		}
		symbol, decimals = t.Symbol, t.Decimals
	}
	raw, ok := new(big.Rat).SetString(er.Intent.Amount)
	if !ok {
		raw = new(big.Rat) // contract calls carry no amount
	}
	tokens := new(big.Rat).Quo(raw, new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)))

	er.PriceStale = w.PriceStale
	if p, ok := ratOf(w.PricesUSD[symbol]); ok && !w.PriceStale {
		er.AmountUSD = decimalString(new(big.Rat).Mul(tokens, p))
	} else {
		er.PriceStale = true
	}
	if bal, ok := ratOf(w.Balances[symbol]); ok && bal.Sign() > 0 {
		er.PctOfBalance = decimalString(new(big.Rat).Quo(tokens, bal))
	}
	dest := strings.ToLower(er.Intent.Destination)
	for _, k := range w.KnownDestinations {
		k = strings.ToLower(k)
		switch {
		case k == dest:
			er.Destination.Known = true
		case len(k) == 42 && len(dest) == 42 && k[:6] == dest[:6] && k[38:] == dest[38:]:
			er.Destination.SimilarToKnown = true // same first/last 4 hex digits (CS-133 does this properly)
		}
	}
	return nil
}

func ratOf(s string) (*big.Rat, bool) {
	if s == "" {
		return nil, false
	}
	return new(big.Rat).SetString(s)
}

// decimalString renders a non-negative r with up to 18 fractional digits,
// rounding up, so downstream conversion never sees less than the truth.
func decimalString(r *big.Rat) *string {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	num := new(big.Int).Mul(r.Num(), scale)
	q, m := new(big.Int).QuoRem(num, r.Denom(), new(big.Int))
	if m.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	ip, fp := new(big.Int).QuoRem(q, scale, new(big.Int))
	s := ip.String()
	if frac := strings.TrimRight(fmt.Sprintf("%018s", fp.String()), "0"); frac != "" {
		s += "." + frac
	}
	return &s
}

// ---- signer (replaced by CS-161) ----

// UnsignedSigner returns a token with header alg "none". Every conforming
// verifier rejects it at decision-token-v1 §4 step 1 (BAD_HEADER), so a dev
// allow can never be used to sign anything.
type UnsignedSigner struct{}

func (UnsignedSigner) Sign(_ context.Context, d model.Decision) (string, error) {
	hdr, err := canon.Marshal(map[string]string{"alg": "none", "typ": "stopbar-dev-unsigned"})
	if err != nil {
		return "", err
	}
	body, err := canon.Marshal(map[string]any{"request_id": d.RequestID, "payload_hash": d.PayloadHash, "outcome": d.Outcome})
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding
	return b64.EncodeToString(hdr) + "." + b64.EncodeToString(body) + ".dev-unsigned", nil
}

// ---- audit (replaced by CS-171) ----

// Audit appends hash-chained JSON lines (spec/audit-hash-v1.md) to W.
type Audit struct {
	W     io.Writer
	Clock func() time.Time

	mu   sync.Mutex
	seq  uint64
	prev string
}

func (a *Audit) Append(_ context.Context, typ model.AuditRecordType, body any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.prev == "" {
		a.prev = canon.GenesisHash
	}
	now := time.Now
	if a.Clock != nil {
		now = a.Clock
	}
	// Round-trip the body through JSON so the hash covers exactly what is written.
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return err
	}
	rec := model.AuditRecord{Seq: a.seq + 1, TS: now().UTC().Format(time.RFC3339Nano), Type: typ, Body: generic, PrevHash: a.prev}
	rec.Hash, err = canon.RecordHash(rec.Seq, rec.TS, string(rec.Type), rec.Body, rec.PrevHash)
	if err != nil {
		return err
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := a.W.Write(append(line, '\n')); err != nil {
		return err
	}
	a.seq, a.prev = rec.Seq, rec.Hash
	return nil
}
