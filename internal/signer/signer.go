// Package signer is the gatekeeper adapter (CS-162): the only component that
// holds wallet keys. It is EDGE code (HLD §4). It uses go-ethereum for
// secp256k1 and EIP-1559 encoding, which the stdlib lacks, but it never
// touches a key until the trusted-core verifier (internal/decision, stdlib
// only) has accepted the decision token for the exact transaction.
//
// SignTx, in order:
//  1. Verify the token (spec §4). This recomputes payload_hash from the
//     exact unsigned tx and spends the token, so one token gives one signature.
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
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Errors.
var (
	ErrNoKey       = errors.New("signer: adapter holds no key for this from address")
	ErrNotBindable = errors.New("signer: transaction does not match its approved payload")
)

// Adapter signs EVM transactions behind a decision-token check.
type Adapter struct {
	verifier *decision.Verifier
	keys     map[common.Address]*ecdsa.PrivateKey
}

// Options for New.
type Options struct {
	// AllowWellKnownTestKeys admits the public Anvil/Hardhat default accounts.
	// stopbard sets it only with -dev-world: people copy example configs, and
	// a known private key in production is an instant drain.
	AllowWellKnownTestKeys bool
}

// New returns an adapter. The verifier must have pinned keys, this adapter's
// audience, and a spent-token store.
func New(v *decision.Verifier, keys []*ecdsa.PrivateKey, opts Options) (*Adapter, error) {
	if v == nil || v.Spent == nil || v.Keys == nil || v.Aud == "" {
		return nil, errors.New("signer: verifier needs pinned keys, an audience and a spent store")
	}
	a := &Adapter{verifier: v, keys: map[common.Address]*ecdsa.PrivateKey{}}
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

// SignTx returns the raw signed transaction and its hash.
func (a *Adapter) SignTx(_ context.Context, token string, act model.Action) ([]byte, common.Hash, error) {
	claims, err := a.verifier.Verify(token, act) // step 1: core first
	if err != nil {
		return nil, common.Hash{}, err
	}
	from := common.HexToAddress(act.From)
	key, ok := a.keys[from]
	if !ok || !strings.EqualFold(from.Hex(), act.From) {
		return nil, common.Hash{}, fmt.Errorf("%w: %s", ErrNoKey, act.From)
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
