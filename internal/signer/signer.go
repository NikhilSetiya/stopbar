// Package signer is the gatekeeper adapter (CS-162): the only component that
// holds wallet keys. It is EDGE code (HLD §4). It uses go-ethereum for
// secp256k1 and EIP-1559 encoding, which the stdlib lacks, but it never
// touches a key until the trusted-core verifier (internal/decision, stdlib
// only) has accepted the decision token for the exact transaction.
//
// SignTx, in order:
//  1. Verify the token (decision-token-v2 §4). This recomputes payload_hash
//     from the exact unsigned tx, requires the token's requester identity to
//     be the authenticated identity of the request being signed, and spends
//     the token, so one token gives one signature. v1 tokens are refused.
//  2. Find the key for `from`. The adapter signs only for addresses it holds.
//  3. Build the transaction from the approved fields only. Nothing is filled
//     in after the decision: nonce, gas and fees were all bound by the token.
//  4. Sign, recover the sender, and require it to equal `from`.
//  5. Re-derive the action from the signed transaction and require its
//     payload hash to equal the token's. A bug in step 3 cannot sign
//     something other than what was approved.
package signer

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Errors.
var (
	ErrNoKey           = errors.New("signer: adapter holds no key for this from address")
	ErrNotBindable     = errors.New("signer: transaction does not match its approved payload")
	ErrDelegatedWallet = errors.New("signer: signing wallet carries unexpected delegation code (EIP-7702)")
	ErrDigestMismatch  = errors.New("signer: off-chain digest does not match the approved payload")
)

// delegationPrefix marks an EIP-7702 delegated account: 0xef0100 followed by
// the 20-byte delegate address (23 bytes total).
var delegationPrefix = []byte{0xef, 0x01, 0x00}

// DelegatedTo returns the address an account's code delegates to under
// EIP-7702, and whether it is such a delegation. A plain EOA has empty code.
func DelegatedTo(code []byte) (common.Address, bool) {
	if len(code) != 23 || !bytesHasPrefix(code, delegationPrefix) {
		return common.Address{}, false
	}
	return common.BytesToAddress(code[3:]), true
}

func bytesHasPrefix(b, prefix []byte) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == string(prefix)
}

// Adapter signs EVM transactions behind a decision-token check.
type Adapter struct {
	verifier *decision.Verifier
	keys     map[common.Address]*ecdsa.PrivateKey
	codeAt   func(context.Context, common.Address) ([]byte, error)
	expected map[common.Address]bool
}

// Options for New.
type Options struct {
	// AllowWellKnownTestKeys admits the public Anvil/Hardhat default accounts.
	// stopbard sets it only with -dev-world: people copy example configs, and
	// a known private key in production is an instant drain.
	AllowWellKnownTestKeys bool
	// CodeAt, when set, is queried for the `from` account's on-chain code
	// before signing. If from carries EIP-7702 delegation code to an address
	// not in ExpectedDelegates, the adapter refuses to sign (a delegated hot
	// wallet can be made to act as another contract). A read error fails
	// closed. nil disables the check (e.g. when the adapter has no chain
	// access yet, CS-146).
	CodeAt func(context.Context, common.Address) ([]byte, error)
	// ExpectedDelegates are delegation targets the operator has vetted; a
	// delegation to any other address is refused.
	ExpectedDelegates map[common.Address]bool
}

// New returns an adapter. The verifier must have pinned keys, this adapter's
// audience, and a spent-token store.
func New(v *decision.Verifier, keys []*ecdsa.PrivateKey, opts Options) (*Adapter, error) {
	if v == nil || v.Spent == nil || v.Keys == nil || v.Aud == "" {
		return nil, errors.New("signer: verifier needs pinned keys, an audience and a spent store")
	}
	a := &Adapter{verifier: v, keys: map[common.Address]*ecdsa.PrivateKey{}, codeAt: opts.CodeAt, expected: opts.ExpectedDelegates}
	for _, k := range keys {
		addr := crypto.PubkeyToAddress(k.PublicKey)
		if isWellKnownTestKey(addr) && !opts.AllowWellKnownTestKeys {
			return nil, fmt.Errorf("%w: %s", ErrWellKnownKey, addr.Hex())
		}
		a.keys[addr] = k
	}
	return a, nil
}

// Addresses lists the wallets this adapter can sign for.
func (a *Adapter) Addresses() []common.Address {
	out := make([]common.Address, 0, len(a.keys))
	for addr := range a.keys {
		out = append(out, addr)
	}
	return out
}

// SignTx returns the raw signed transaction and its hash. requester is the
// authenticated identity of the request act came from (the zero Identity
// when auth is off); a token bound to any other identity is refused.
func (a *Adapter) SignTx(ctx context.Context, token string, act model.Action, requester auth.Identity) ([]byte, common.Hash, error) {
	if act.Kind != model.KindEVMTx {
		return nil, common.Hash{}, ErrNotBindable
	}
	claims, err := a.verifier.Verify(token, act, requester) // step 1: core first
	if err != nil {
		return nil, common.Hash{}, err
	}
	from, key, err := a.keyFor(ctx, act.From) // step 2
	if err != nil {
		return nil, common.Hash{}, err
	}
	tx, err := buildTx(act) // step 3
	if err != nil {
		return nil, common.Hash{}, err
	}
	s := types.LatestSignerForChainID(tx.ChainId())
	signed, err := types.SignTx(tx, s, key) // step 4
	if err != nil {
		return nil, common.Hash{}, fmt.Errorf("signer: %w", err)
	}
	sender, err := types.Sender(s, signed)
	if err != nil || sender != from {
		return nil, common.Hash{}, fmt.Errorf("signer: recovered sender %s, want %s", sender.Hex(), from.Hex())
	}
	back, err := ActionOf(signed) // step 5
	if err != nil {
		return nil, common.Hash{}, err
	}
	if ph, err := decision.PayloadHash(back); err != nil || ph != claims.PayloadHash {
		return nil, common.Hash{}, ErrNotBindable
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return nil, common.Hash{}, err
	}
	return raw, signed.Hash(), nil
}

// keyFor returns the key for from, refusing an address the adapter doesn't
// hold and a wallet carrying unexpected EIP-7702 delegation code.
func (a *Adapter) keyFor(ctx context.Context, fromHex string) (common.Address, *ecdsa.PrivateKey, error) {
	from := common.HexToAddress(fromHex)
	key, ok := a.keys[from]
	if !ok || !strings.EqualFold(from.Hex(), fromHex) {
		return from, nil, fmt.Errorf("%w: %s", ErrNoKey, fromHex)
	}
	if a.codeAt != nil { // refuse to sign for a delegated (EIP-7702) wallet
		code, err := a.codeAt(ctx, from)
		if err != nil {
			return from, nil, fmt.Errorf("%w: code read failed: %v", ErrDelegatedWallet, err)
		}
		if to, ok := DelegatedTo(code); ok && !a.expected[to] {
			return from, nil, fmt.Errorf("%w: %s -> %s", ErrDelegatedWallet, from.Hex(), to.Hex())
		}
	}
	return from, key, nil
}

// SignMessage answers an off-chain signature request (evm_typed_data,
// evm_personal_sign; CS-514) with a 65-byte signature (v = 27/28) and the
// digest it signs. In order:
//  1. Verify the token (decision-token-v2 §4) against the exact action, as
//     SignTx does. The core binds the typed data's bytes, never a digest.
//  2. Find the key for `from` (and refuse a delegated wallet).
//  3. Compute the digest from the bound action only: EIP-712 for typed data
//     (whose domain.chainId must equal the action's chain_id), EIP-191 for
//     personal_sign. No digest from the requester is ever accepted.
//  4. Recompute the digest from the payload's canonical bytes (what
//     payload_hash covers) and refuse any mismatch, so the signer cannot hash
//     anything other than what was bound.
//  5. Sign, recover the signer, and require it to equal `from`.
func (a *Adapter) SignMessage(ctx context.Context, token string, act model.Action, requester auth.Identity) ([]byte, common.Hash, error) {
	if act.Kind != model.KindEVMTypedData && act.Kind != model.KindEVMPersonalSign {
		return nil, common.Hash{}, ErrNotBindable
	}
	if _, err := a.verifier.Verify(token, act, requester); err != nil { // step 1: core first
		return nil, common.Hash{}, err
	}
	from, key, err := a.keyFor(ctx, act.From) // step 2
	if err != nil {
		return nil, common.Hash{}, err
	}
	digest, err := MessageDigest(act) // step 3
	if err != nil {
		return nil, common.Hash{}, err
	}
	canonical, err := decision.CanonicalAction(act) // step 4
	if err != nil {
		return nil, common.Hash{}, err
	}
	var bound model.Action
	if err := json.Unmarshal(canonical, &bound); err != nil {
		return nil, common.Hash{}, fmt.Errorf("signer: canonical action: %w", err)
	}
	bound.Kind, bound.ChainID = act.Kind, act.ChainID
	if again, err := MessageDigest(bound); err != nil || again != digest {
		return nil, common.Hash{}, fmt.Errorf("%w: digest of the bound payload differs", ErrDigestMismatch)
	}
	sig, err := crypto.Sign(digest[:], key) // step 5
	if err != nil {
		return nil, common.Hash{}, fmt.Errorf("signer: %w", err)
	}
	pub, err := crypto.SigToPub(digest[:], sig)
	if err != nil || crypto.PubkeyToAddress(*pub) != from {
		return nil, common.Hash{}, fmt.Errorf("%w: recovered signer is not %s", ErrDigestMismatch, from.Hex())
	}
	sig[64] += 27 // the v wallets and ecrecover expect
	return sig, digest, nil
}

// MessageDigest is the hash a wallet signs for an off-chain request: the
// EIP-712 digest of typed data, or the EIP-191 personal_sign hash.
func MessageDigest(act model.Action) (common.Hash, error) {
	switch act.Kind {
	case model.KindEVMPersonalSign:
		msg, err := hexutil.Decode(act.Message)
		if err != nil || len(msg) == 0 {
			return common.Hash{}, fmt.Errorf("%w: personal_sign message is not hex", ErrNotBindable)
		}
		return common.BytesToHash(accounts.TextHash(msg)), nil
	case model.KindEVMTypedData:
		if act.TypedData == nil || act.ChainID == nil {
			return common.Hash{}, ErrNotBindable
		}
		raw, err := json.Marshal(act.TypedData)
		if err != nil {
			return common.Hash{}, err
		}
		var td apitypes.TypedData
		if err := json.Unmarshal(raw, &td); err != nil {
			return common.Hash{}, fmt.Errorf("%w: typed data: %v", ErrNotBindable, err)
		}
		if td.Domain.ChainId == nil || (*big.Int)(td.Domain.ChainId).Cmp(new(big.Int).SetUint64(*act.ChainID)) != 0 {
			return common.Hash{}, fmt.Errorf("%w: domain.chainId is not the action's chain_id", ErrNotBindable)
		}
		h, _, err := apitypes.TypedDataAndHash(td)
		if err != nil {
			return common.Hash{}, fmt.Errorf("%w: EIP-712: %v", ErrNotBindable, err)
		}
		return common.BytesToHash(h), nil
	}
	return common.Hash{}, ErrNotBindable
}

func decimal(name, v string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(v, 10)
	if !ok || n.Sign() < 0 {
		return nil, fmt.Errorf("signer: %s %q is not a non-negative integer", name, v)
	}
	return n, nil
}

// buildTx constructs the EIP-1559 transaction from the action's fields and
// nothing else.
func buildTx(a model.Action) (*types.Transaction, error) {
	if a.Kind != model.KindEVMTx || a.ChainID == nil || a.TxType == nil || *a.TxType != 2 {
		return nil, ErrNotBindable
	}
	vals := map[string]*big.Int{}
	for name, v := range map[string]string{"value_wei": a.ValueWei, "tx_nonce": a.TxNonce, "gas_limit": a.GasLimit,
		"max_fee_per_gas": a.MaxFeePerGas, "max_priority_fee_per_gas": a.MaxPriorityFeePerGas} {
		n, err := decimal(name, v)
		if err != nil {
			return nil, err
		}
		vals[name] = n
	}
	if !vals["tx_nonce"].IsUint64() || !vals["gas_limit"].IsUint64() {
		return nil, ErrNotBindable
	}
	data, err := hexutil.Decode(orEmpty(a.Data))
	if err != nil {
		return nil, fmt.Errorf("signer: data: %w", err)
	}
	if !common.IsHexAddress(a.To) {
		return nil, ErrNotBindable
	}
	to := common.HexToAddress(a.To)
	return types.NewTx(&types.DynamicFeeTx{
		ChainID:   new(big.Int).SetUint64(*a.ChainID),
		Nonce:     vals["tx_nonce"].Uint64(),
		GasTipCap: vals["max_priority_fee_per_gas"],
		GasFeeCap: vals["max_fee_per_gas"],
		Gas:       vals["gas_limit"].Uint64(),
		To:        &to,
		Value:     vals["value_wei"],
		Data:      data,
	}), nil
}

func orEmpty(d string) string {
	if d == "" {
		return "0x"
	}
	return d
}

// ActionOf reads a signed EIP-1559 transaction back into an action (with the
// recovered sender as from). Used to check what was signed, and by
// `stopbar decode-tx`.
func ActionOf(tx *types.Transaction) (model.Action, error) {
	if tx.Type() != types.DynamicFeeTxType || tx.To() == nil || len(tx.AccessList()) != 0 {
		return model.Action{}, ErrNotBindable
	}
	from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil {
		return model.Action{}, err
	}
	chain, two := tx.ChainId().Uint64(), 2
	data := hexutil.Encode(tx.Data()) // "0x" when empty
	return model.Action{
		Kind: model.KindEVMTx, ChainID: &chain, From: strings.ToLower(from.Hex()), To: strings.ToLower(tx.To().Hex()),
		ValueWei: tx.Value().String(), Data: data, TxType: &two,
		TxNonce: fmt.Sprint(tx.Nonce()), GasLimit: fmt.Sprint(tx.Gas()),
		MaxFeePerGas: tx.GasFeeCap().String(), MaxPriorityFeePerGas: tx.GasTipCap().String(),
	}, nil
}

// DecodeRaw parses raw signed transaction bytes.
func DecodeRaw(raw []byte) (*types.Transaction, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return tx, nil
}

// ---- dev wallet keys (local provider; replaced by KMS/Turnkey in CS-163/164) ----

const walletFileTag = "stopbar-dev-wallet-secp256k1-v1\n"

// LoadDevWallet reads hex secp256k1 keys (one per line) from a tagged file
// that only its owner can read. The tag keeps decision keys and wallet keys
// from ever being loaded as each other.
func LoadDevWallet(path string) ([]*ecdsa.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("signer: wallet file %s has mode %o; must be 0600 or stricter", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rest, ok := strings.CutPrefix(string(b), walletFileTag)
	if !ok {
		return nil, fmt.Errorf("signer: %s is not a Stopbar dev wallet file", path)
	}
	var keys []*ecdsa.PrivateKey
	for _, line := range strings.Split(rest, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := crypto.HexToECDSA(strings.TrimPrefix(line, "0x"))
		if err != nil {
			return nil, fmt.Errorf("signer: %s: bad key: %w", path, err)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("signer: %s holds no keys", path)
	}
	return keys, nil
}

// WriteDevWallet writes keys (hex) to a tagged 0600 file.
func WriteDevWallet(path string, hexKeys ...string) error {
	return os.WriteFile(path, []byte(walletFileTag+strings.Join(hexKeys, "\n")+"\n"), 0o600)
}
