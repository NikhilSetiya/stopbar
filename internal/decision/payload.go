// Package decision is the decision token (spec/decision-token-v1.md): the
// payload binding, Ed25519 signing, key rotation and the verifier signer
// adapters run before signing anything. It is part of the trusted core:
// stdlib only, with compact JWS hand-rolled, so no JOSE library.
package decision

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/NikhilSetiya/stopbar/internal/canon"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

const maxSafeInt = 1 << 53

// ErrNoBinding is returned for actions that have no payload binding in v1
// (contract creation, withdrawal). No token may be issued for them.
var ErrNoBinding = errors.New("decision: action has no payload binding in v1")

// CanonicalAction returns the JCS bytes that payload_hash covers
// (decision-token-v1 §2). The action must already pass model validation.
func CanonicalAction(a model.Action) ([]byte, error) {
	var obj map[string]any
	switch a.Kind {
	case model.KindEVMTx:
		if a.ChainID == nil || *a.ChainID == 0 || *a.ChainID >= maxSafeInt {
			return nil, errors.New("decision: evm_tx chain_id must be in [1, 2^53)")
		}
		if a.To == "" {
			return nil, fmt.Errorf("%w: evm_tx without to (contract creation)", ErrNoBinding)
		}
		v, ok := new(big.Int).SetString(a.ValueWei, 10)
		if !ok || v.Sign() < 0 {
			return nil, errors.New("decision: evm_tx value_wei must be a non-negative decimal string")
		}
		if a.TxType == nil || *a.TxType != 2 {
			return nil, fmt.Errorf("%w: only EIP-1559 (tx_type 2) transactions can be bound", ErrNoBinding)
		}
		fields := map[string]string{}
		for name, raw := range map[string]string{
			"tx_nonce": a.TxNonce, "gas_limit": a.GasLimit,
			"max_fee_per_gas": a.MaxFeePerGas, "max_priority_fee_per_gas": a.MaxPriorityFeePerGas,
		} {
			n, ok := new(big.Int).SetString(raw, 10)
			if !ok || n.Sign() < 0 {
				return nil, fmt.Errorf("decision: evm_tx %s must be a non-negative decimal string", name)
			}
			fields[name] = n.String()
		}
		data := strings.ToLower(a.Data)
		if data == "" {
			data = "0x" // one spelling of empty calldata
		}
		// Every field of the unsigned transaction: the adapter signs exactly
		// this and fills in nothing after the decision.
		obj = map[string]any{
			"v": 1, "kind": "evm_tx", "tx_type": 2, "chain_id": *a.ChainID,
			"from": strings.ToLower(a.From), "to": strings.ToLower(a.To),
			"value_wei": v.String(), "data": data,
			"tx_nonce": fields["tx_nonce"], "gas_limit": fields["gas_limit"],
			"max_fee_per_gas": fields["max_fee_per_gas"], "max_priority_fee_per_gas": fields["max_priority_fee_per_gas"],
		}
	case model.KindToolCall:
		if a.Tool == nil || *a.Tool == "" {
			return nil, errors.New("decision: tool_call tool required")
		}
		args := a.Args
		if args == nil {
			args = map[string]any{}
		}
		obj = map[string]any{"v": 1, "kind": "tool_call", "tool": *a.Tool, "args": args}
	default:
		return nil, fmt.Errorf("%w: kind %q", ErrNoBinding, a.Kind)
	}
	return canon.Marshal(obj)
}

// PayloadHash is "sha256:<hex>" of CanonicalAction(a).
func PayloadHash(a model.Action) (string, error) {
	c, err := CanonicalAction(a)
	if err != nil {
		return "", err
	}
	return canon.Digest(c), nil
}
