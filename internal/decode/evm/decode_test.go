package evm

import (
	"context"
	"encoding/hex"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

const (
	wallet   = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	token    = "0x1111111111111111111111111111111111111111"
	token2   = "0x5555555555555555555555555555555555555555"
	attacker = "0x9999999999999999999999999999999999999999"
	friend   = "0x4444444444444444444444444444444444444444"
	router   = "0x2222222222222222222222222222222222222222"
	safe     = "0x3333333333333333333333333333333333333333"
	multiSnd = "0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761"
	weth     = "0x4200000000000000000000000000000000000006"
)

func tx(to string, value string, data []byte) model.Action {
	chain, two := uint64(8453), 2
	return model.Action{Kind: model.KindEVMTx, ChainID: &chain, From: wallet, To: to, ValueWei: value, Data: hx(data),
		TxType: &two, TxNonce: "0", GasLimit: "200000", MaxFeePerGas: "2000000000", MaxPriorityFeePerGas: "1000000000"}
}

func decode(t *testing.T, a model.Action) model.IntentSummary {
	t.Helper()
	in, err := Decoder{}.Decode(context.Background(), a)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return in
}

// packed MultiSend entry: operation | to | value | len | data
func msEntry(op byte, to string, value int64, data []byte) []byte {
	b := []byte{op}
	a, _ := hex.DecodeString(strings.TrimPrefix(to, "0x"))
	b = append(b, a...)
	b = append(b, word(big.NewInt(value))...)
	b = append(b, word(big.NewInt(int64(len(data))))...)
	return append(b, data...)
}

func v3path(tokens ...string) []byte {
	var b []byte
	for i, tk := range tokens {
		a, _ := hex.DecodeString(strings.TrimPrefix(tk, "0x"))
		b = append(b, a...)
		if i < len(tokens)-1 {
			b = append(b, 0x00, 0x0b, 0xb8) // fee 3000
		}
	}
	return b
}

func TestGolden(t *testing.T) {
	transferTo := func(dst string, n int64) []byte { return calldata(selTransfer, addrV(dst), u(n)) }
	approveMax := calldata(selApprove, addrV(attacker), ub(maxBits(256)))
	safeExec := func(to string, value int64, data []byte, op int64) []byte {
		return calldata(selExecTransaction, addrV(to), u(value), bytesV(data), u(op), u(0), u(0), u(0),
			addrV("0x0000000000000000000000000000000000000000"), addrV("0x0000000000000000000000000000000000000000"), bytesV([]byte{1, 2, 3}))
	}
	nested := transferTo(friend, 1)
	for range 6 {
		nested = calldata(selMulticall, arrV{bytesV(nested)})
	}

	for _, tt := range []struct {
		name               string
		a                  model.Action
		kind, op           string
		asset, amount, dst string
		flags              []string
		calls              int
	}{
		{"native transfer", tx(friend, "1000", nil), "transfer", "native_transfer", "", "1000", friend, nil, 0},
		{"erc20 transfer", tx(token, "0", transferTo(friend, 50)), "transfer", "erc20_transfer", token, "50", friend, nil, 0},
		{"erc20 approve unlimited", tx(token, "0", approveMax), "approve", "erc20_approve", token, maxBits(256).String(), attacker, []string{FlagUnlimitedApproval}, 0},
		{"erc20 approve bounded", tx(token, "0", calldata(selApprove, addrV(router), u(100))), "approve", "erc20_approve", token, "100", router, nil, 0},
		{"increaseAllowance unlimited", tx(token, "0", calldata(selIncreaseAllowance, addrV(attacker), ub(maxBits(255)))), "approve", "erc20_approve", token, maxBits(255).String(), attacker, []string{FlagUnlimitedApproval}, 0},
		{"transferFrom a third party", tx(token, "0", calldata(selTransferFrom, addrV(friend), addrV(attacker), u(7))), "transfer", "transfer_from", token, "7", attacker, []string{FlagThirdPartyFrom}, 0},
		{"transferFrom own funds", tx(token, "0", calldata(selTransferFrom, addrV(wallet), addrV(friend), u(7))), "transfer", "transfer_from", token, "7", friend, nil, 0},
		{"setApprovalForAll on", tx(token, "0", calldata(selSetApprovalForAll, addrV(attacker), boolV(true))), "approve", "set_approval_for_all", token, "", attacker, []string{FlagUnlimitedApproval}, 0},
		{"setApprovalForAll off", tx(token, "0", calldata(selSetApprovalForAll, addrV(attacker), boolV(false))), "approve", "revoke_approval_for_all", token, "0", attacker, nil, 0},
		{"erc1155 transfer", tx(token, "0", calldata(selSafeTransferFrom1155, addrV(wallet), addrV(friend), u(3), u(2), bytesV(nil))), "transfer", "erc1155_transfer", token, "2", friend, nil, 0},
		{"erc2612 permit unlimited", tx(token, "0", calldata(selPermit2612, addrV(wallet), addrV(attacker), ub(maxBits(256)), u(9), u(27), u(1), u(2))), "approve", "erc2612_permit", token, maxBits(256).String(), attacker, []string{FlagUnlimitedApproval}, 0},
		{"permit2 approve unlimited", tx(router, "0", calldata(selP2Approve, addrV(token), addrV(attacker), ub(maxBits(160)), u(99))), "approve", "permit2_approve", token, maxBits(160).String(), attacker, []string{FlagUnlimitedApproval}, 0},
		{"permit2 permit single", tx(router, "0", calldata(selP2PermitSingle, addrV(wallet), tupV{tupV{addrV(token), u(500), u(1), u(0)}, addrV(router), u(9)}, bytesV([]byte{1}))), "approve", "permit2_permit", token, "500", router, nil, 0},
		{"permit2 permit batch", tx(router, "0", calldata(selP2PermitBatch, addrV(wallet), tupV{arrV{tupV{addrV(token), u(5), u(1), u(0)}, tupV{addrV(token2), ub(maxBits(160)), u(1), u(0)}}, addrV(attacker), u(9)}, bytesV([]byte{1}))), "contract_call", "permit2_permit_batch", "", "", "", []string{FlagUnlimitedApproval}, 2},
		{"permit2 transferFrom", tx(router, "0", calldata(selP2TransferFrom, addrV(wallet), addrV(friend), u(5), addrV(token))), "transfer", "permit2_transfer_from", token, "5", friend, nil, 0},
		// Batches: a flag can't hide inside one.
		{"multicall hides an unlimited approve", tx(token, "0", calldata(selMulticall, arrV{bytesV(approveMax), bytesV(transferTo(friend, 9))})), "transfer", "multicall", token, "9", friend, []string{FlagUnlimitedApproval}, 2},
		{"multicall with deadline", tx(token, "0", calldata(selMulticallDeadline, u(123), arrV{bytesV(transferTo(friend, 9))})), "transfer", "multicall", token, "9", friend, nil, 1},
		{"aggregate3 with two transfers", tx(router, "0", calldata(selAggregate3, arrV{tupV{addrV(token), boolV(false), bytesV(transferTo(friend, 1))}, tupV{addrV(token2), boolV(true), bytesV(transferTo(attacker, 2))}})), "contract_call", "aggregate3", "", "", "", []string{FlagMultiTransfer}, 2},
		{"aggregate (v1)", tx(router, "0", calldata(selAggregate, arrV{tupV{addrV(token), bytesV(transferTo(friend, 4))}})), "transfer", "aggregate", token, "4", friend, nil, 1},
		{"aggregate3Value native out", tx(router, "10", calldata(selAggregate3Value, arrV{tupV{addrV(attacker), boolV(false), u(10), bytesV(nil)}})), "transfer", "aggregate3_value", "", "10", attacker, nil, 1},
		{"too deep is opaque", tx(token, "0", nested), "contract_call", "multicall", "", "", "", []string{FlagOpaque}, 1},
		// Safe
		{"safe call", tx(safe, "0", safeExec(token, 0, transferTo(friend, 3), 0)), "transfer", "safe_exec", token, "3", friend, nil, 1},
		{"safe delegatecall (Bybit pattern)", tx(safe, "0", safeExec(attacker, 0, calldata("12345678", u(1)), 1)), "contract_call", "safe_exec", "", "", "", []string{FlagDelegatecall, FlagUnknownCall}, 1},
		{"safe batch via canonical MultiSend", tx(safe, "0", safeExec(multiSnd, 0, calldata(selMultiSend, bytesV(append(msEntry(0, token, 0, transferTo(friend, 1)), msEntry(0, token2, 0, transferTo(friend, 2))...))), 1)), "contract_call", "safe_exec", "", "", "", []string{FlagMultiTransfer}, 1},
		{"multisend entry delegatecalls", tx(safe, "0", safeExec(multiSnd, 0, calldata(selMultiSend, bytesV(msEntry(1, attacker, 0, calldata("deadbeef")))), 1)), "contract_call", "safe_exec", "", "", "", []string{FlagDelegatecall, FlagUnknownCall}, 1},
		{"safe master copy change", tx(safe, "0", calldata(selChangeMasterCopy, addrV(attacker))), "contract_call", "proxy_upgrade", "", "", attacker, []string{FlagProxyUpgrade}, 0},
		{"proxy upgradeTo", tx(router, "0", calldata(selUpgradeTo, addrV(attacker))), "contract_call", "proxy_upgrade", "", "", attacker, []string{FlagProxyUpgrade}, 0},
		{"safe owner added", tx(safe, "0", calldata(selAddOwnerWithThreshold, addrV(attacker), u(1))), "contract_call", "wallet_admin", "", "", safe, []string{FlagWalletAdmin}, 0},
		// Swaps
		{"v2 exact-in zero min out", tx(router, "0", calldata(selV2SwapExactTokensForTokens, u(1000), u(0), arrV{addrV(token), addrV(token2)}, addrV(wallet), u(1))), "transfer", "swap_exact_in", token, "1000", wallet, []string{FlagMinOutZero}, 0},
		{"v2 exact-in protected", tx(router, "0", calldata(selV2SwapExactTokensForTokens, u(1000), u(990), arrV{addrV(token), addrV(token2)}, addrV(wallet), u(1))), "transfer", "swap_exact_in", token, "1000", wallet, nil, 0},
		{"v2 ETH in, output to attacker", tx(router, "500", calldata(selV2SwapExactETHForTokens, u(1), arrV{addrV(weth), addrV(token)}, addrV(attacker), u(1))), "transfer", "swap_exact_in", "", "500", attacker, nil, 0},
		{"v2 exact-out", tx(router, "0", calldata(selV2SwapTokensForExactTokens, u(10), u(2000), arrV{addrV(token), addrV(token2)}, addrV(wallet), u(1))), "transfer", "swap_exact_out", token, "2000", wallet, nil, 0},
		{"v3 exactInputSingle (router02) zero min", tx(router, "0", calldata(selR02ExactInputSingle, tupV{addrV(token), addrV(token2), u(3000), addrV(wallet), u(77), u(0), u(0)})), "transfer", "swap_exact_in", token, "77", wallet, []string{FlagMinOutZero}, 0},
		{"v3 exactInputSingle (v1)", tx(router, "0", calldata(selV3ExactInputSingle, tupV{addrV(token), addrV(token2), u(3000), addrV(wallet), u(1), u(77), u(70), u(0)})), "transfer", "swap_exact_in", token, "77", wallet, nil, 0},
		{"v3 exactInput multi-hop", tx(router, "0", calldata(selV3ExactInput, tupV{bytesV(v3path(token, weth, token2)), addrV(wallet), u(1), u(88), u(80)})), "transfer", "swap_exact_in", token, "88", wallet, nil, 0},
		{"v3 exactOutput reverses the path", tx(router, "0", calldata(selR02ExactOutput, tupV{bytesV(v3path(token2, weth, token)), addrV(wallet), u(5), u(99)})), "transfer", "swap_exact_out", token, "99", wallet, nil, 0},
		{"universal router: permit2 max + v2 swap, zero min", tx(router, "0", calldata(selURExecute, bytesV([]byte{urPermit2Permit, urV2SwapExactIn}),
			arrV{bytesV(encodeSeq([]val{tupV{tupV{addrV(token), ub(maxBits(160)), u(1), u(0)}, addrV(router), u(9)}, bytesV([]byte{1})})),
				bytesV(encodeSeq([]val{addrV("0x0000000000000000000000000000000000000001"), u(1000), u(0), arrV{addrV(token), addrV(token2)}, boolV(true)}))}, u(1))),
			"transfer", "universal_router", token, "1000", wallet, []string{FlagMinOutZero, FlagUnlimitedApproval}, 2},
		{"universal router: v3 swap to attacker", tx(router, "0", calldata(selURExecuteNoDeadline, bytesV([]byte{urV3SwapExactIn | 0x80}),
			arrV{bytesV(encodeSeq([]val{addrV(attacker), u(5), u(4), bytesV(v3path(token, token2)), boolV(true)}))})),
			"transfer", "universal_router", token, "5", attacker, nil, 1},
		{"universal router: unknown command is opaque", tx(router, "0", calldata(selURExecuteNoDeadline, bytesV([]byte{0x21}), arrV{bytesV(nil)})), "contract_call", "universal_router", "", "", "", []string{FlagOpaque}, 1},
		// Other
		{"weth wrap (deposit on the chain WETH)", tx(weth, "100000000000000000", calldata("d0e30db0")), "contract_call", "weth_wrap", "", "100000000000000000", weth, nil, 0},
		{"weth unwrap (withdraw on the chain WETH)", tx(weth, "0", calldata("2e1a7d4d", u(50000000000000000))), "contract_call", "weth_unwrap", "", "50000000000000000", weth, nil, 0},
		{"deposit() on a non-WETH address stays unknown", tx(token, "0", calldata("d0e30db0")), "contract_call", "unknown", "", "", token, []string{FlagUnknownCall}, 0},
		{"withdraw() on a non-WETH address stays unknown", tx(token, "0", calldata("2e1a7d4d", u(1))), "contract_call", "unknown", "", "", token, []string{FlagUnknownCall}, 0},
		{"unknown selector", tx(router, "0", calldata("deadbeef", u(1))), "contract_call", "unknown", "", "", router, []string{FlagUnknownCall}, 0},
		{"value attached to a multicall is its own outflow", tx(router, "7", calldata(selMulticall, arrV{bytesV(transferTo(friend, 9))})), "contract_call", "call_with_value", "", "", "", []string{FlagMultiTransfer}, 2},
		{"value to an unknown call inside a batch is an outflow", tx(router, "3", calldata(selAggregate3Value, arrV{tupV{addrV(attacker), boolV(false), u(3), bytesV(calldata("deadbeef"))}, tupV{addrV(token), boolV(false), u(0), bytesV(transferTo(friend, 1))}})), "contract_call", "aggregate3_value", "", "", "", []string{FlagMultiTransfer, FlagUnknownCall}, 2},
		{"token transfer with ETH attached", tx(token, "5", transferTo(friend, 9)), "contract_call", "call_with_value", "", "", "", []string{FlagMultiTransfer}, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := decode(t, tt.a)
			asset := ""
			if in.Asset != nil {
				asset = in.Asset.Address
			}
			want := tt.flags
			if want == nil {
				want = []string{}
			}
			if in.Kind != tt.kind || in.Op != tt.op || asset != tt.asset || in.Amount != tt.amount || in.Destination != tt.dst ||
				!slices.Equal(in.Flags, want) || len(in.Calls) != tt.calls {
				t.Fatalf("got kind=%s op=%s asset=%s amount=%s dst=%s flags=%v calls=%d\nwant kind=%s op=%s asset=%s amount=%s dst=%s flags=%v calls=%d\nhuman: %s",
					in.Kind, in.Op, asset, in.Amount, in.Destination, in.Flags, len(in.Calls),
					tt.kind, tt.op, tt.asset, tt.amount, tt.dst, want, tt.calls, in.Human)
			}
			if in.Human == "" {
				t.Fatal("no human rendering")
			}
		})
	}
}

func TestFeesPerChain(t *testing.T) {
	drain := tx(friend, "0", nil) // CS-2026-0007 on Base: 30M gas at 5,000 gwei
	drain.GasLimit, drain.MaxFeePerGas = "30000000", "5000000000000"
	if in := decode(t, drain); !slices.Contains(in.Flags, FlagExcessiveFee) {
		t.Fatalf("fee drain not flagged: %v", in.Flags)
	}
	if in := decode(t, tx(friend, "1", nil)); slices.Contains(in.Flags, FlagExcessiveFee) {
		t.Fatal("normal Base fee flagged")
	}
	// The same 300 gwei is normal on Polygon and excessive on Base.
	busy := tx(friend, "1", nil)
	busy.MaxFeePerGas, busy.GasLimit = "300000000000", "21000"
	if in := decode(t, busy); !slices.Contains(in.Flags, FlagExcessiveFee) {
		t.Fatal("300 gwei on Base not flagged")
	}
	polygon := uint64(137)
	busy.ChainID = &polygon
	if in := decode(t, busy); slices.Contains(in.Flags, FlagExcessiveFee) {
		t.Fatal("300 gwei on Polygon flagged")
	}
	other := uint64(999999)
	busy.ChainID = &other
	if _, err := (Decoder{}).Decode(context.Background(), busy); err == nil {
		t.Fatal("unsupported chain decoded; must fail closed")
	}
}

func TestMalformedKnownCallsFailClosed(t *testing.T) {
	short := calldata(selTransfer, addrV(friend)) // missing the amount word
	highBytes := calldata(selTransfer, u(1), u(1))
	highBytes[4] = 0xff // address word with non-zero high bytes
	badOffset := calldata(selMulticall, arrV{bytesV([]byte{1, 2, 3, 4})})
	badOffset[4+31] = 0xff // head offset points past the end
	for name, data := range map[string][]byte{"short": short, "address high bytes": highBytes, "bad offset": badOffset} {
		if _, err := (Decoder{}).Decode(context.Background(), tx(token, "0", data)); err == nil {
			t.Errorf("%s: decoded; must be an error", name)
		}
	}
}

// The devstub decoder's corpus behaviour is preserved: kind and flags for
// the shapes the corpus uses are unchanged.
func TestCompatibleWithCorpusShapes(t *testing.T) {
	in := decode(t, tx(token, "0", calldata(selTransfer, addrV(friend), u(1))))
	if in.Kind != "transfer" || in.Asset == nil || in.Asset.ChainID != 8453 {
		t.Fatalf("%+v", in)
	}
}

func FuzzDecode(f *testing.F) {
	for _, d := range [][]byte{
		calldata(selTransfer, addrV(friend), u(1)),
		calldata(selMulticall, arrV{bytesV(calldata(selApprove, addrV(attacker), u(1)))}),
		calldata(selURExecuteNoDeadline, bytesV([]byte{urV2SwapExactIn}), arrV{bytesV(encodeSeq([]val{addrV(wallet), u(1), u(0), arrV{addrV(token), addrV(token2)}, boolV(true)}))}),
		calldata(selMultiSend, bytesV(msEntry(0, token, 0, calldata(selTransfer, addrV(friend), u(1))))),
	} {
		f.Add(d)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := Decoder{}.Decode(context.Background(), tx(router, "0", data))
		if err == nil && in.Flags == nil {
			t.Fatal("nil flags")
		}
	})
}
