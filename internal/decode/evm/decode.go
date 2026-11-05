// Package evm decodes an unsigned EVM transaction into the intent the policy
// evaluates (LLD §6, CS-141/142/145). It renders what the transaction will do
// independently of whatever the requester claims, recursing into multicalls,
// Safe transactions, MultiSend batches and Universal Router commands, and
// raises a flag for each risky pattern.
//
// Stdlib only: this package decides what the policy sees.
package evm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Flags (LLD §6.2). Destination flags (new/similar/first-time) need the
// tenant's registry, so the enricher adds those.
const (
	FlagUnlimitedApproval = "unlimited_approval"
	FlagDelegatecall      = "delegatecall"
	FlagProxyUpgrade      = "proxy_upgrade"
	FlagWalletAdmin       = "wallet_admin" // Safe owner, threshold, module or guard change
	FlagOpaque            = "opaque"
	FlagUnknownCall       = "unknown_call"
	FlagMinOutZero        = "min_out_zero"
	FlagExcessiveFee      = "excessive_fee"
	FlagMultiTransfer     = "multi_transfer"
	FlagThirdPartyFrom    = "third_party_from" // transferFrom pulls from an address other than the sender
)

// MaxDepth is how deep calls may nest before the rest is opaque (LLD §6.1).
const MaxDepth = 4

// Policy actions (the Cedar actions an evm_tx maps to).
const (
	kindTransfer = "transfer"
	kindApprove  = "approve"
	kindCall     = "contract_call"
)

// Decoder implements engine.Decoder for evm_tx actions.
type Decoder struct{}

func (Decoder) Supports(a model.Action) bool { return a.Kind == model.KindEVMTx }

// Decode renders the whole transaction. A malformed call to a known
// selector, or an unsupported chain, is an error (the engine fails closed);
// an unknown selector is a flag (the policy decides).
func (Decoder) Decode(_ context.Context, a model.Action) (model.IntentSummary, error) {
	if a.ChainID == nil {
		return model.IntentSummary{}, errors.New("evm: chain_id missing")
	}
	value, err := dec("value_wei", a.ValueWei)
	if err != nil {
		return model.IntentSummary{}, err
	}
	gas, err := dec("gas_limit", a.GasLimit)
	if err != nil {
		return model.IntentSummary{}, err
	}
	fee, err := dec("max_fee_per_gas", a.MaxFeePerGas)
	if err != nil {
		return model.IntentSummary{}, err
	}
	data, err := hexData(a.Data)
	if err != nil {
		return model.IntentSummary{}, err
	}
	d := &decoder{chain: *a.ChainID, from: strings.ToLower(a.From)}
	in, err := d.call(strings.ToLower(a.To), value, data, 0)
	if err != nil {
		return model.IntentSummary{}, err
	}
	in.Target = ""
	excessive, why, err := excessiveFee(*a.ChainID, gas, fee)
	if err != nil {
		return model.IntentSummary{}, err
	}
	if excessive {
		in.Flags = append(in.Flags, FlagExcessiveFee)
		in.Human += " (" + why + ")"
	}
	in.Flags = union(in.Flags)
	return in, nil
}

type decoder struct {
	chain uint64
	from  string // the transaction sender
}

func (d *decoder) asset(addr string) *model.Asset {
	return &model.Asset{ChainID: d.chain, Address: addr}
}

// call decodes one call: target `to`, native `value`, calldata `data`.
func (d *decoder) call(to string, value *big.Int, data []byte, depth int) (model.IntentSummary, error) {
	if len(data) == 0 {
		return model.IntentSummary{
			Kind: kindTransfer, Op: "native_transfer", Target: to, Amount: value.String(), Destination: to, Flags: []string{},
			Human: fmt.Sprintf("Send %s wei (native) to %s", value, to),
		}, nil
	}
	if depth > MaxDepth {
		return opaque(to, "nested deeper than %d calls", MaxDepth), nil
	}
	if len(data) < 4 {
		return unknown(to, value), nil
	}
	sel, p := hex.EncodeToString(data[:4]), args(data[4:])
	in, ok, err := d.known(sel, to, value, p, depth)
	if err != nil {
		return model.IntentSummary{}, fmt.Errorf("evm: %s on %s: %w", Signatures[sel], to, err)
	}
	if !ok {
		return unknown(to, value), nil
	}
	in.Target = to
	if in.Flags == nil {
		in.Flags = []string{}
	}
	// Native value sent along with a call that doesn't spend it is a second
	// outflow; keep both visible.
	if value.Sign() > 0 && !spendsValue(in.Op) {
		native := model.IntentSummary{Kind: kindTransfer, Op: "native_transfer", Target: to, Amount: value.String(),
			Destination: to, Flags: []string{}, Human: fmt.Sprintf("Send %s wei (native) to %s", value, to)}
		return batch("call_with_value", to, []model.IntentSummary{native, in}), nil
	}
	return in, nil
}

// spendsValue: operations whose decoding accounts for msg.value (ETH-in
// swaps, per-call values, Safe inner value, router commands). For anything
// else, attached value is shown as its own outflow, so a multicall can't
// carry native value the intent doesn't show.
func spendsValue(op string) bool {
	switch op {
	case "swap_exact_in", "swap_exact_out", "aggregate3_value", "safe_exec", "universal_router":
		return true
	}
	return false
}

func (d *decoder) known(sel, to string, value *big.Int, p args, depth int) (model.IntentSummary, bool, error) {
	switch sel {
	case selTransfer:
		dst, amt, err := addrUint(p, 0, 1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		return model.IntentSummary{Kind: kindTransfer, Op: "erc20_transfer", Asset: d.asset(to), Amount: amt.String(), Destination: dst,
			Human: fmt.Sprintf("Transfer %s units of token %s to %s", amt, to, dst)}, true, nil

	case selTransferFrom, selSafeTransferFrom721, selSafeTransferFrom721Data:
		src, err := p.address(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		dst, amt, err := addrUint(p, 1, 2)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in := model.IntentSummary{Kind: kindTransfer, Op: "transfer_from", Asset: d.asset(to), Amount: amt.String(), Destination: dst,
			Human: fmt.Sprintf("Move %s (amount or token ID) of %s from %s to %s", amt, to, src, dst)}
		if src != d.from {
			in.Flags = []string{FlagThirdPartyFrom}
		}
		return in, true, nil

	case selSafeTransferFrom1155:
		src, err := p.address(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		dst, err := p.address(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		id, err := p.uint(2)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		amt, err := p.uint(3)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in := model.IntentSummary{Kind: kindTransfer, Op: "erc1155_transfer", Asset: d.asset(to), Amount: amt.String(), Destination: dst,
			Human: fmt.Sprintf("Move %s of token ID %s in %s from %s to %s", amt, id, to, src, dst)}
		if src != d.from {
			in.Flags = []string{FlagThirdPartyFrom}
		}
		return in, true, nil

	case selSafeBatchTransfer1155:
		src, err := p.address(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		dst, err := p.address(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in := model.IntentSummary{Kind: kindTransfer, Op: "erc1155_batch_transfer", Asset: d.asset(to), Destination: dst,
			Flags: []string{FlagMultiTransfer}, Human: fmt.Sprintf("Move several token IDs of %s from %s to %s", to, src, dst)}
		if src != d.from {
			in.Flags = append(in.Flags, FlagThirdPartyFrom)
		}
		return in, true, nil

	case selApprove, selIncreaseAllowance:
		spender, amt, err := addrUint(p, 0, 1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in := model.IntentSummary{Kind: kindApprove, Op: "erc20_approve", Asset: d.asset(to), Amount: amt.String(), Destination: spender,
			Human: fmt.Sprintf("Allow %s to spend %s units of token %s", spender, amt, to)}
		if isMax(amt, 255) {
			in.Flags = []string{FlagUnlimitedApproval}
		}
		return in, true, nil

	case selPermit2612:
		spender, err := p.address(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		amt, err := p.uint(2)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in := model.IntentSummary{Kind: kindApprove, Op: "erc2612_permit", Asset: d.asset(to), Amount: amt.String(), Destination: spender,
			Human: fmt.Sprintf("Submit a permit letting %s spend %s units of token %s", spender, amt, to)}
		if isMax(amt, 255) {
			in.Flags = []string{FlagUnlimitedApproval}
		}
		return in, true, nil

	case selSetApprovalForAll:
		op, err := p.address(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		on, err := p.boolean(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		if !on {
			return model.IntentSummary{Kind: kindApprove, Op: "revoke_approval_for_all", Asset: d.asset(to), Amount: "0", Destination: op,
				Human: fmt.Sprintf("Revoke %s as operator of every token in %s", op, to)}, true, nil
		}
		return model.IntentSummary{Kind: kindApprove, Op: "set_approval_for_all", Asset: d.asset(to), Destination: op,
			Flags: []string{FlagUnlimitedApproval}, Human: fmt.Sprintf("Let %s move every token in %s", op, to)}, true, nil

	case selP2Approve:
		token, err := p.address(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		spender, amt, err := addrUint(p, 1, 2)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		return d.permit2("permit2_approve", token, spender, amt), true, nil

	case selP2PermitSingle:
		// owner, then PermitSingle inline: token, amount, expiration, nonce, spender, sigDeadline; then sig offset
		token, err := p.address(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		amt, err := p.uint(2)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		spender, err := p.address(5)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		return d.permit2("permit2_permit", token, spender, amt), true, nil

	case selP2PermitBatch:
		t, err := p.tail(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		spender, err := t.address(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		n, el, err := t.array(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		var calls []model.IntentSummary
		for k := range n {
			token, err := el.address(4 * k)
			if err != nil {
				return model.IntentSummary{}, true, err
			}
			amt, err := el.uint(4*k + 1)
			if err != nil {
				return model.IntentSummary{}, true, err
			}
			calls = append(calls, d.permit2("permit2_permit", token, spender, amt))
		}
		return batch("permit2_permit_batch", to, calls), true, nil

	case selP2TransferFrom:
		src, err := p.address(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		dst, amt, err := addrUint(p, 1, 2)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		token, err := p.address(3)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in := model.IntentSummary{Kind: kindTransfer, Op: "permit2_transfer_from", Asset: d.asset(token), Amount: amt.String(), Destination: dst,
			Human: fmt.Sprintf("Move %s units of token %s from %s to %s via Permit2", amt, token, src, dst)}
		if src != d.from {
			in.Flags = []string{FlagThirdPartyFrom}
		}
		return in, true, nil

	case selMulticall, selMulticallDeadline, selMulticallPrevBlock:
		idx := 0
		if sel != selMulticall {
			idx = 1
		}
		inner, err := p.bytesArray(idx)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		calls := make([]model.IntentSummary, 0, len(inner))
		for _, b := range inner { // delegatecall to self: each inner call targets the same contract
			c, err := d.call(to, new(big.Int), b, depth+1)
			if err != nil {
				return model.IntentSummary{}, true, err
			}
			calls = append(calls, c)
		}
		return batch("multicall", to, calls), true, nil

	case selAggregate, selTryAggregate, selAggregate3, selAggregate3Value:
		idx, dataWord, valueWord, op := 0, 1, -1, "aggregate"
		switch sel {
		case selTryAggregate:
			idx = 1
		case selAggregate3:
			dataWord, op = 2, "aggregate3"
		case selAggregate3Value:
			dataWord, valueWord, op = 3, 2, "aggregate3_value"
		}
		tuples, err := p.tupleArray(idx)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		calls := make([]model.IntentSummary, 0, len(tuples))
		for _, t := range tuples {
			target, err := t.address(0)
			if err != nil {
				return model.IntentSummary{}, true, err
			}
			v := new(big.Int)
			if valueWord >= 0 {
				if v, err = t.uint(valueWord); err != nil {
					return model.IntentSummary{}, true, err
				}
			}
			b, err := t.bytesAt(dataWord)
			if err != nil {
				return model.IntentSummary{}, true, err
			}
			c, err := d.call(target, v, b, depth+1)
			if err != nil {
				return model.IntentSummary{}, true, err
			}
			calls = append(calls, c)
		}
		return batch(op, to, calls), true, nil

	case selExecTransaction:
		return d.safeExec(to, p, depth)

	case selMultiSend:
		packed, err := p.bytesAt(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in, err := d.multiSend(to, packed, depth)
		return in, true, err

	case selUpgradeTo, selUpgradeToAndCall, selChangeMasterCopy, selSetFallbackHandler:
		impl, err := p.address(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		return model.IntentSummary{Kind: kindCall, Op: "proxy_upgrade", Destination: impl, Flags: []string{FlagProxyUpgrade},
			Human: fmt.Sprintf("Change the code or handler behind %s to %s", to, impl)}, true, nil

	case selAddOwnerWithThreshold, selRemoveOwner, selSwapOwner, selChangeThreshold, selEnableModule, selSetGuard:
		return model.IntentSummary{Kind: kindCall, Op: "wallet_admin", Destination: to, Flags: []string{FlagWalletAdmin},
			Human: fmt.Sprintf("Change who controls the Safe %s (%s)", to, Signatures[sel])}, true, nil
	}
	if in, ok, err := d.swap(sel, to, value, p); ok || err != nil {
		return in, true, err
	}
	if sel == selURExecute || sel == selURExecuteNoDeadline {
		in, err := d.universalRouter(to, value, p, depth)
		return in, true, err
	}
	return model.IntentSummary{}, false, nil
}

func (d *decoder) permit2(op, token, spender string, amt *big.Int) model.IntentSummary {
	in := model.IntentSummary{Kind: kindApprove, Op: op, Target: "", Asset: d.asset(token), Amount: amt.String(), Destination: spender, Flags: []string{},
		Human: fmt.Sprintf("Allow %s to spend %s units of token %s through Permit2", spender, amt, token)}
	if isMax(amt, 159) { // uint160: the Permit2 maximum
		in.Flags = []string{FlagUnlimitedApproval}
	}
	return in
}

// safeExec decodes execTransaction(to, value, data, operation, ...). The
// inner call runs as the Safe. operation 1 is a delegatecall: the target's
// code runs with the Safe's storage and funds. Only a delegatecall to a
// canonical MultiSend carrying multiSend is the normal batch path.
func (d *decoder) safeExec(safe string, p args, depth int) (model.IntentSummary, bool, error) {
	target, err := p.address(0)
	if err != nil {
		return model.IntentSummary{}, true, err
	}
	v, err := p.uint(1)
	if err != nil {
		return model.IntentSummary{}, true, err
	}
	data, err := p.bytesAt(2)
	if err != nil {
		return model.IntentSummary{}, true, err
	}
	operation, err := p.small(3)
	if err != nil {
		return model.IntentSummary{}, true, err
	}
	if operation > 1 {
		return model.IntentSummary{}, true, fmt.Errorf("operation %d", operation)
	}
	inner := &decoder{chain: d.chain, from: safe}
	c, err := inner.call(target, v, data, depth+1)
	if err != nil {
		return model.IntentSummary{}, true, err
	}
	canonicalBatch := multiSendContracts[target] && c.Op == "multisend"
	if operation == 1 && !canonicalBatch {
		c.Flags = append(c.Flags, FlagDelegatecall)
		c.Human = "DELEGATECALL (runs foreign code as the Safe): " + c.Human
	}
	out := batch("safe_exec", safe, []model.IntentSummary{c})
	out.Human = fmt.Sprintf("Safe %s executes: %s", safe, c.Human)
	return out, true, nil
}

// multiSend decodes MultiSend's packed transactions:
// operation (1) | to (20) | value (32) | data length (32) | data.
func (d *decoder) multiSend(to string, b []byte, depth int) (model.IntentSummary, error) {
	var calls []model.IntentSummary
	for i := 0; i < len(b); {
		if len(b)-i < 85 {
			return model.IntentSummary{}, fmt.Errorf("%w: multiSend entry at %d", errShort, i)
		}
		operation := b[i]
		target := "0x" + hex.EncodeToString(b[i+1:i+21])
		v := new(big.Int).SetBytes(b[i+21 : i+53])
		n := new(big.Int).SetBytes(b[i+53 : i+85])
		if !n.IsInt64() || n.Int64() > int64(len(b)-i-85) {
			return model.IntentSummary{}, fmt.Errorf("multiSend entry at %d: bad data length", i)
		}
		data := b[i+85 : i+85+int(n.Int64())]
		if operation > 1 {
			return model.IntentSummary{}, fmt.Errorf("multiSend entry at %d: operation %d", i, operation)
		}
		c, err := d.call(target, v, data, depth+1)
		if err != nil {
			return model.IntentSummary{}, err
		}
		if operation == 1 {
			c.Flags = append(c.Flags, FlagDelegatecall)
		}
		calls = append(calls, c)
		i += 85 + int(n.Int64())
	}
	return batch("multisend", to, calls), nil
}

// swap decodes Uniswap V2/V3 router and SwapRouter02 swaps. The intent is the
// input leaving the wallet (asset, amount, or the maximum for exact-out), and
// its destination is whoever receives the output. min_out_zero: an exact-in
// swap that accepts any output at all (a sandwich invitation).
func (d *decoder) swap(sel, router string, value *big.Int, p args) (model.IntentSummary, bool, error) {
	type layout struct {
		exactIn  bool
		ethIn    bool // amountIn is msg.value; path starts with WETH
		amtIn    int  // word index of amountIn (exact-in) or amountInMax (exact-out); -1: msg.value
		amtOut   int  // word index of amountOutMin (exact-in) or amountOut (exact-out)
		path, to int
	}
	v2 := map[string]layout{
		selV2SwapExactTokensForTokens:    {true, false, 0, 1, 2, 3},
		selV2SwapExactTokensForTokensFOT: {true, false, 0, 1, 2, 3},
		selV2SwapExactTokensForETH:       {true, false, 0, 1, 2, 3},
		selV2SwapExactTokensForETHFOT:    {true, false, 0, 1, 2, 3},
		selV2SwapExactETHForTokens:       {true, true, -1, 0, 1, 2},
		selV2SwapExactETHForTokensFOT:    {true, true, -1, 0, 1, 2},
		selV2SwapTokensForExactTokens:    {false, false, 1, 0, 2, 3},
		selV2SwapTokensForExactETH:       {false, false, 1, 0, 2, 3},
		selV2SwapETHForExactTokens:       {false, true, -1, 0, 1, 2},
		selR02SwapExactTokensForTokens:   {true, false, 0, 1, 2, 3},
		selR02SwapTokensForExactTokens:   {false, false, 1, 0, 2, 3},
	}
	if l, ok := v2[sel]; ok {
		path, err := p.addressArray(l.path)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		if len(path) < 2 {
			return model.IntentSummary{}, true, errors.New("swap path shorter than 2")
		}
		recipient, err := p.address(l.to)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in := value
		if l.amtIn >= 0 {
			if in, err = p.uint(l.amtIn); err != nil {
				return model.IntentSummary{}, true, err
			}
		}
		out, err := p.uint(l.amtOut)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		tokenIn := path[0]
		if l.ethIn {
			tokenIn = ""
		}
		return d.swapIntent(l.exactIn, tokenIn, path[len(path)-1], in, out, recipient), true, nil
	}

	// V3 single-hop: static tuple inline.
	// SwapRouter:   tokenIn, tokenOut, fee, recipient, deadline, amount, limit, sqrtPrice
	// SwapRouter02: tokenIn, tokenOut, fee, recipient, amount, limit, sqrtPrice
	single := map[string][3]int{ // exactIn(1/0), amount word, limit word
		selV3ExactInputSingle:   {1, 5, 6},
		selV3ExactOutputSingle:  {0, 6, 5},
		selR02ExactInputSingle:  {1, 4, 5},
		selR02ExactOutputSingle: {0, 5, 4},
	}
	if l, ok := single[sel]; ok {
		tokenIn, err := p.address(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		tokenOut, err := p.address(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		recipient, err := p.address(3)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in, err := p.uint(l[1])
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		out, err := p.uint(l[2])
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		return d.swapIntent(l[0] == 1, d.ethOr(tokenIn, value), tokenOut, in, out, recipient), true, nil
	}

	// V3 multi-hop: dynamic tuple (path, recipient, [deadline,] amount, limit).
	multi := map[string][3]int{
		selV3ExactInput:   {1, 3, 4},
		selV3ExactOutput:  {0, 4, 3},
		selR02ExactInput:  {1, 2, 3},
		selR02ExactOutput: {0, 3, 2},
	}
	if l, ok := multi[sel]; ok {
		t, err := p.tail(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		path, err := t.bytesAt(0)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		first, last, err := v3Path(path)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		if l[0] == 0 { // exact-out paths are encoded output-first
			first, last = last, first
		}
		recipient, err := t.address(1)
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		in, err := t.uint(l[1])
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		out, err := t.uint(l[2])
		if err != nil {
			return model.IntentSummary{}, true, err
		}
		return d.swapIntent(l[0] == 1, d.ethOr(first, value), last, in, out, recipient), true, nil
	}
	return model.IntentSummary{}, false, nil
}

// ethOr: a V3 swap paid with msg.value (wrapped by the router) spends native.
func (d *decoder) ethOr(tokenIn string, value *big.Int) string {
	if value.Sign() > 0 {
		return ""
	}
	return tokenIn
}

func (d *decoder) swapIntent(exactIn bool, tokenIn, tokenOut string, in, out *big.Int, recipient string) model.IntentSummary {
	op, verb := "swap_exact_out", "at most "
	if exactIn {
		op, verb = "swap_exact_in", ""
	}
	var asset *model.Asset
	inName := "native"
	if tokenIn != "" {
		asset, inName = d.asset(tokenIn), "token "+tokenIn
	}
	in2 := model.IntentSummary{Kind: kindTransfer, Op: op, Asset: asset, Amount: in.String(), Destination: recipient, Flags: []string{},
		Human: fmt.Sprintf("Swap %s%s units of %s for token %s (min out %s), sent to %s", verb, in, inName, tokenOut, out, recipient)}
	if exactIn && out.Sign() == 0 {
		in2.Flags = []string{FlagMinOutZero}
		in2.Human += " — accepts ANY output (no slippage protection)"
	}
	return in2
}

// v3Path returns the first and last token of a packed V3 path:
// token (20) | fee (3) | token (20) | ...
func v3Path(b []byte) (string, string, error) {
	if len(b) < 43 || (len(b)-20)%23 != 0 {
		return "", "", fmt.Errorf("bad V3 path length %d", len(b))
	}
	return "0x" + hex.EncodeToString(b[:20]), "0x" + hex.EncodeToString(b[len(b)-20:]), nil
}

// Universal Router command bytes (mask 0x3f; 0x80 allows revert).
const (
	urV3SwapExactIn       = 0x00
	urV3SwapExactOut      = 0x01
	urPermit2TransferFrom = 0x02
	urSweep               = 0x04
	urTransfer            = 0x05
	urPayPortion          = 0x06
	urV2SwapExactIn       = 0x08
	urV2SwapExactOut      = 0x09
	urPermit2Permit       = 0x0a
	urWrapETH             = 0x0b
	urUnwrapWETH          = 0x0c
)

// universalRouter decodes execute(commands, inputs[, deadline]).
func (d *decoder) universalRouter(router string, value *big.Int, p args, depth int) (model.IntentSummary, error) {
	cmds, err := p.bytesAt(0)
	if err != nil {
		return model.IntentSummary{}, err
	}
	inputs, err := p.bytesArray(1)
	if err != nil {
		return model.IntentSummary{}, err
	}
	if len(cmds) != len(inputs) {
		return model.IntentSummary{}, fmt.Errorf("%d commands but %d inputs", len(cmds), len(inputs))
	}
	recipient := func(a string) string { // Universal Router constants
		switch a {
		case "0x0000000000000000000000000000000000000001":
			return d.from // MSG_SENDER
		case "0x0000000000000000000000000000000000000002":
			return router // ADDRESS_THIS
		}
		return a
	}
	calls := make([]model.IntentSummary, 0, len(cmds))
	for i, c := range cmds {
		in := args(inputs[i])
		var ci model.IntentSummary
		var err error
		switch c & 0x3f {
		case urV2SwapExactIn, urV2SwapExactOut, urV3SwapExactIn, urV3SwapExactOut:
			ci, err = d.urSwap(c&0x3f, in, value, recipient)
		case urPermit2Permit: // PermitSingle inline: token, amount, expiration, nonce, spender, sigDeadline; sig
			var token, spender string
			var amt *big.Int
			if token, err = in.address(0); err == nil {
				if amt, err = in.uint(1); err == nil {
					spender, err = in.address(4)
				}
			}
			if err == nil {
				ci = d.permit2("permit2_permit", token, spender, amt)
			}
		case urPermit2TransferFrom, urTransfer: // (token, recipient, amount)
			var token, dst string
			var amt *big.Int
			if token, err = in.address(0); err == nil {
				if dst, err = in.address(1); err == nil {
					amt, err = in.uint(2)
				}
			}
			if err == nil {
				ci = model.IntentSummary{Kind: kindTransfer, Op: "router_transfer", Asset: d.asset(token), Amount: amt.String(),
					Destination: recipient(dst), Flags: []string{}, Human: fmt.Sprintf("Router sends %s units of token %s to %s", amt, token, recipient(dst))}
			}
		case urSweep, urPayPortion, urWrapETH, urUnwrapWETH: // output plumbing: who receives
			w := 1
			if c&0x3f == urWrapETH || c&0x3f == urUnwrapWETH {
				w = 0
			}
			var dst string
			if dst, err = in.address(w); err == nil {
				ci = model.IntentSummary{Kind: kindCall, Op: "router_output", Destination: recipient(dst), Flags: []string{},
					Human: fmt.Sprintf("Router pays output to %s", recipient(dst))}
			}
		default:
			ci = opaque(router, "Universal Router command 0x%02x is not decoded", c)
		}
		if err != nil {
			return model.IntentSummary{}, fmt.Errorf("command %d (0x%02x): %w", i, c, err)
		}
		ci.Target = router
		calls = append(calls, ci)
	}
	return batch("universal_router", router, calls), nil
}

func (d *decoder) urSwap(cmd byte, in args, value *big.Int, recipient func(string) string) (model.IntentSummary, error) {
	// (recipient, amount, limit, path, payerIsUser): V2 path is address[], V3 is packed bytes.
	to, err := in.address(0)
	if err != nil {
		return model.IntentSummary{}, err
	}
	a1, err := in.uint(1)
	if err != nil {
		return model.IntentSummary{}, err
	}
	a2, err := in.uint(2)
	if err != nil {
		return model.IntentSummary{}, err
	}
	exactIn := cmd == urV2SwapExactIn || cmd == urV3SwapExactIn
	var first, last string
	if cmd == urV2SwapExactIn || cmd == urV2SwapExactOut {
		path, err := in.addressArray(3)
		if err != nil {
			return model.IntentSummary{}, err
		}
		if len(path) < 2 {
			return model.IntentSummary{}, errors.New("swap path shorter than 2")
		}
		first, last = path[0], path[len(path)-1]
	} else {
		path, err := in.bytesAt(3)
		if err != nil {
			return model.IntentSummary{}, err
		}
		if first, last, err = v3Path(path); err != nil {
			return model.IntentSummary{}, err
		}
		if !exactIn {
			first, last = last, first
		}
	}
	amtIn, amtOut := a1, a2 // exact-in: amountIn, amountOutMin
	if !exactIn {
		amtIn, amtOut = a2, a1 // exact-out: amountInMax, amountOut
	}
	return d.swapIntent(exactIn, d.ethOr(first, value), last, amtIn, amtOut, recipient(to)), nil
}

// batch wraps inner calls. Flags are the union of every inner flag; if
// exactly one inner call moves value, its asset, amount, destination and
// kind are hoisted (so pricing, caps and the policy action see it).
func batch(op, to string, calls []model.IntentSummary) model.IntentSummary {
	out := model.IntentSummary{Kind: kindCall, Op: op, Target: to, Calls: calls, Flags: []string{}}
	var movers []model.IntentSummary
	kinds := map[string]bool{}
	parts := make([]string, 0, len(calls))
	for _, c := range calls {
		out.Flags = append(out.Flags, c.Flags...)
		kinds[c.Kind] = true
		parts = append(parts, c.Human)
		if c.Amount != "" && c.Kind != kindApprove { // any outflow, including value sent to an unknown call
			movers = append(movers, c)
		} else if c.Op == "erc1155_batch_transfer" {
			movers = append(movers, c, c) // never hoisted: several IDs
		}
	}
	switch {
	case len(movers) == 1:
		m := movers[0]
		out.Kind, out.Asset, out.Amount, out.Destination = m.Kind, m.Asset, m.Amount, m.Destination
	case len(movers) > 1:
		out.Flags = append(out.Flags, FlagMultiTransfer)
	case kinds[kindApprove] && len(calls) == 1:
		c := calls[0]
		out.Kind, out.Asset, out.Amount, out.Destination = c.Kind, c.Asset, c.Amount, c.Destination
	}
	out.Flags = union(out.Flags)
	out.Human = fmt.Sprintf("%s of %d call(s): %s", op, len(calls), strings.Join(parts, "; "))
	return out
}

func unknown(to string, value *big.Int) model.IntentSummary {
	in := model.IntentSummary{Kind: kindCall, Op: "unknown", Target: to, Destination: to, Flags: []string{FlagUnknownCall},
		Human: fmt.Sprintf("Call contract %s with undecoded calldata", to)}
	if value.Sign() > 0 {
		in.Amount, in.Human = value.String(), in.Human+fmt.Sprintf(", sending %s wei", value)
	}
	return in
}

func opaque(to, why string, a ...any) model.IntentSummary {
	return model.IntentSummary{Kind: kindCall, Op: "opaque", Target: to, Destination: to, Flags: []string{FlagOpaque},
		Human: fmt.Sprintf("Opaque call to %s: "+why, append([]any{to}, a...)...)}
}

func addrUint(p args, ai, ui int) (string, *big.Int, error) {
	a, err := p.address(ai)
	if err != nil {
		return "", nil, err
	}
	u, err := p.uint(ui)
	return a, u, err
}

func dec(name, s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Sign() < 0 {
		return nil, fmt.Errorf("evm: %s %q is not a non-negative integer", name, s)
	}
	return n, nil
}

func hexData(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("evm: data is not hex: %w", err)
	}
	return b, nil
}

func union(flags []string) []string {
	out := slices.Clone(flags)
	slices.Sort(out)
	return slices.Compact(out)
}
