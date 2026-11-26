package evm

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Clock for long_expiry: 2026-11-02T10:00:00Z.
var offNow = time.Unix(1762077600, 0)

const (
	usdc    = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
	seaport = "0x0000000000000068f116a894984e2db1123eb395"
	nft     = "0x5555555555555555555555555555555555555555"
	signer  = "0x2222222222222222222222222222222222222222"
)

func typedAction(t *testing.T, td string) model.Action {
	t.Helper()
	var d model.TypedData
	if err := json.Unmarshal([]byte(td), &d); err != nil {
		t.Fatal(err)
	}
	chain := uint64(8453)
	return model.Action{Kind: model.KindEVMTypedData, ChainID: &chain, From: signer, TypedData: &d}
}

func fixtureAction(t *testing.T) model.Action {
	t.Helper()
	b, err := os.ReadFile("../../../spec/fixtures/action_request.evm_typed_data.json")
	if err != nil {
		t.Fatal(err)
	}
	var r model.ActionRequest
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.Action
}

const domain2612 = `"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}]`

func permit2612(value, deadline string) string {
	return `{"types":{` + domain2612 + `,"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},
	"primaryType":"Permit","domain":{"name":"USD Coin","version":"2","chainId":8453,"verifyingContract":"` + usdc + `"},
	"message":{"owner":"` + signer + `","spender":"0x9f30000000000000000000000000000000000c21","value":"` + value + `","nonce":"0","deadline":"` + deadline + `"}}`
}

func daiPermitTD(allowed, expiry string) string {
	return `{"types":{` + domain2612 + `,"Permit":[{"name":"holder","type":"address"},{"name":"spender","type":"address"},{"name":"nonce","type":"uint256"},{"name":"expiry","type":"uint256"},{"name":"allowed","type":"bool"}]},
	"primaryType":"Permit","domain":{"name":"Dai","version":"1","chainId":8453,"verifyingContract":"` + usdc + `"},
	"message":{"holder":"` + signer + `","spender":"0x9f30000000000000000000000000000000000c21","nonce":"0","expiry":"` + expiry + `","allowed":` + allowed + `}}`
}

const p2types = `"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
"PermitDetails":[{"name":"token","type":"address"},{"name":"amount","type":"uint160"},{"name":"expiration","type":"uint48"},{"name":"nonce","type":"uint48"}]`

func permitBatchTD(amt1, amt2 string) string {
	return `{"types":{` + p2types + `,"PermitBatch":[{"name":"details","type":"PermitDetails[]"},{"name":"spender","type":"address"},{"name":"sigDeadline","type":"uint256"}]},
	"primaryType":"PermitBatch","domain":{"name":"Permit2","chainId":8453,"verifyingContract":"` + Permit2 + `"},
	"message":{"details":[{"token":"` + usdc + `","amount":"` + amt1 + `","expiration":"1762200000","nonce":"0"},{"token":"` + token + `","amount":"` + amt2 + `","expiration":"1762200000","nonce":"0"}],
	"spender":"0x9f30000000000000000000000000000000000c21","sigDeadline":"1762078800"}}`
}

const seaportTypes = `"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
"OrderComponents":[{"name":"offerer","type":"address"},{"name":"zone","type":"address"},{"name":"offer","type":"OfferItem[]"},{"name":"consideration","type":"ConsiderationItem[]"},{"name":"orderType","type":"uint8"},{"name":"startTime","type":"uint256"},{"name":"endTime","type":"uint256"},{"name":"zoneHash","type":"bytes32"},{"name":"salt","type":"uint256"},{"name":"conduitKey","type":"bytes32"},{"name":"counter","type":"uint256"}],
"OfferItem":[{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"}],
"ConsiderationItem":[{"name":"itemType","type":"uint8"},{"name":"token","type":"address"},{"name":"identifierOrCriteria","type":"uint256"},{"name":"startAmount","type":"uint256"},{"name":"endAmount","type":"uint256"},{"name":"recipient","type":"address"}]`

const zero32 = "0x0000000000000000000000000000000000000000000000000000000000000000"

func seaportTD(offer, consideration string) string {
	return `{"types":{` + seaportTypes + `},"primaryType":"OrderComponents",
	"domain":{"name":"Seaport","version":"1.6","chainId":8453,"verifyingContract":"` + seaport + `"},
	"message":{"offerer":"` + signer + `","zone":"0x0000000000000000000000000000000000000000","offer":[` + offer + `],"consideration":[` + consideration + `],
	"orderType":0,"startTime":"1762077600","endTime":"1764669600","zoneHash":"` + zero32 + `","salt":"1","conduitKey":"` + zero32 + `","counter":"0"}}`
}

const (
	nftOffer   = `{"itemType":2,"token":"` + nft + `","identifierOrCriteria":"42","startAmount":"1","endAmount":"1"}`
	payMe      = `{"itemType":0,"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":"0","startAmount":"970000000000000000","endAmount":"970000000000000000","recipient":"` + signer + `"}`
	payFee     = `{"itemType":0,"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":"0","startAmount":"30000000000000000","endAmount":"30000000000000000","recipient":"0x0000a26b00c1f0df003000390027140000faa719"}`
	payMeZero  = `{"itemType":0,"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":"0","startAmount":"0","endAmount":"0","recipient":"` + signer + `"}`
	payThief   = `{"itemType":0,"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":"0","startAmount":"1","endAmount":"1","recipient":"0x9f30000000000000000000000000000000000c21"}`
	mailTD     = `{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],"Mail":[{"name":"to","type":"address"},{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Ether Mail","chainId":8453},"message":{"to":"0x1111111111111111111111111111111111111111","contents":"Hello, Bob!"}}`
	maxU160    = "1461501637330902918203684832716283019655932542975"
	maxU256    = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
	in10days   = "1762941600"
	in2years   = "1825149600"
	uint48Max  = "281474976710655"
	pastFiveAM = "1762059600"
)

func TestDecodeTypedData(t *testing.T) {
	p2 := func(mut func(m map[string]any)) model.Action {
		a := fixtureAction(t)
		mut(a.TypedData.Message["details"].(map[string]any))
		return a
	}
	for _, tt := range []struct {
		name                    string
		a                       model.Action
		kind, op, asset, amount string
		dest, expiry            string
		flags                   []string
		calls                   int
		humanHas                string
		isError                 bool
	}{
		{name: "permit2 single bounded (benign, renders)", a: fixtureAction(t), kind: "approve", op: "permit2_permit_signature", asset: usdc, amount: "250000000",
			dest: "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", expiry: "1764064800", flags: []string{}, humanHas: "Sign a Permit2 permit letting 0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad spend 250000000 units"},
		{name: "permit2 single max amount", a: p2(func(m map[string]any) { m["amount"] = maxU160 }), kind: "approve", op: "permit2_permit_signature", asset: usdc, amount: maxU160,
			dest: "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", expiry: "1764064800", flags: []string{FlagUnlimitedApproval}},
		{name: "permit2 single never expires", a: p2(func(m map[string]any) { m["expiration"] = uint48Max }), kind: "approve", op: "permit2_permit_signature", asset: usdc, amount: "250000000",
			dest: "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", expiry: uint48Max, flags: []string{FlagLongExpiry}, humanHas: "effectively never"},
		{name: "permit2 batch, one unlimited", a: typedAction(t, permitBatchTD("5", maxU160)), kind: "approve", op: "permit2_permit_batch_signature",
			dest: "", expiry: "1762200000", flags: []string{FlagUnlimitedApproval}, calls: 2},
		{name: "eip-2612 permit bounded", a: typedAction(t, permit2612("1000000", in10days)), kind: "approve", op: "erc2612_permit_signature", asset: usdc, amount: "1000000",
			dest: "0x9f30000000000000000000000000000000000c21", expiry: in10days, flags: []string{}},
		{name: "eip-2612 permit unlimited forever", a: typedAction(t, permit2612(maxU256, maxU256)), kind: "approve", op: "erc2612_permit_signature", asset: usdc, amount: maxU256,
			dest: "0x9f30000000000000000000000000000000000c21", expiry: maxU256, flags: []string{FlagLongExpiry, FlagUnlimitedApproval}},
		{name: "eip-2612 permit two years", a: typedAction(t, permit2612("1", in2years)), kind: "approve", op: "erc2612_permit_signature", asset: usdc, amount: "1",
			dest: "0x9f30000000000000000000000000000000000c21", expiry: in2years, flags: []string{FlagLongExpiry}},
		{name: "dai permit allowed, expiry 0 = never", a: typedAction(t, daiPermitTD("true", "0")), kind: "approve", op: "dai_permit_signature", asset: usdc, amount: maxU256,
			dest: "0x9f30000000000000000000000000000000000c21", expiry: "0", flags: []string{FlagLongExpiry, FlagUnlimitedApproval}, humanHas: "never expires"},
		{name: "dai permit revoke", a: typedAction(t, daiPermitTD("false", pastFiveAM)), kind: "approve", op: "dai_permit_revoke_signature", asset: usdc, amount: "0",
			dest: "0x9f30000000000000000000000000000000000c21", flags: []string{}},
		{name: "seaport listing paid", a: typedAction(t, seaportTD(nftOffer, payMe+","+payFee)), kind: "transfer", op: "seaport_order", asset: nft, amount: "1",
			expiry: "1764669600", flags: []string{}, humanHas: "you receive 970000000000000000 wei (native); others receive 30000000000000000 wei (native) to 0x0000a26b"},
		{name: "seaport zero-price listing", a: typedAction(t, seaportTD(nftOffer, payMeZero)), kind: "transfer", op: "seaport_order", asset: nft, amount: "1",
			expiry: "1764669600", flags: []string{FlagZeroConsideration}, humanHas: "you receive 0 wei (native), NOTHING"},
		{name: "seaport pays someone else", a: typedAction(t, seaportTD(nftOffer, payThief)), kind: "transfer", op: "seaport_order", asset: nft, amount: "1",
			expiry: "1764669600", flags: []string{FlagZeroConsideration}, humanHas: "to 0x9f30000000000000000000000000000000000c21"},
		{name: "seaport two offers", a: typedAction(t, seaportTD(nftOffer+","+nftOffer, payMe)), kind: "transfer", op: "seaport_order",
			expiry: "1764669600", flags: []string{FlagMultiTransfer}},
		{name: "unknown typed data renders", a: typedAction(t, mailTD), kind: "sign_message", op: "typed_data",
			flags: []string{FlagUnknownCall}, humanHas: `Sign Mail typed data on chain 8453 (domain "Ether Mail"): {"contents":"Hello, Bob!","to":"0x1111111111111111111111111111111111111111"}`},
		{name: "look-alike PermitSingle", a: typedAction(t, strings.Replace(permitBatchTD("1", "1"), `"PermitBatch"`, `"PermitSingle"`, 2)), isError: true},
		{name: "permit owner is not the signer", a: typedAction(t, strings.Replace(permit2612("1", in10days), `"owner":"`+signer, `"owner":"0x1111111111111111111111111111111111111111`, 1)), isError: true},
		{name: "seaport offerer is not the signer", a: typedAction(t, strings.Replace(seaportTD(nftOffer, payMe), `"offerer":"`+signer, `"offerer":"0x1111111111111111111111111111111111111111`, 1)), isError: true},
		{name: "seaport bad item type", a: typedAction(t, seaportTD(strings.Replace(nftOffer, `"itemType":2`, `"itemType":6`, 1), payMe)), isError: true},
		{name: "invalid typed data", a: typedAction(t, strings.Replace(mailTD, `"Hello, Bob!"`, `7`, 1)), isError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in, err := Decoder{Now: func() time.Time { return offNow }}.Decode(context.Background(), tt.a)
			if tt.isError {
				if err == nil {
					t.Fatalf("decoded %+v; want an error", in)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			asset := ""
			if in.Asset != nil {
				asset = in.Asset.Address
			}
			if in.Kind != tt.kind || in.Op != tt.op || asset != tt.asset || in.Amount != tt.amount || in.Destination != tt.dest || in.Expiry != tt.expiry || len(in.Calls) != tt.calls {
				t.Errorf("got kind=%s op=%s asset=%s amount=%s dest=%s expiry=%s calls=%d", in.Kind, in.Op, asset, in.Amount, in.Destination, in.Expiry, len(in.Calls))
			}
			if !slices.Equal(in.Flags, tt.flags) {
				t.Errorf("flags %v, want %v", in.Flags, tt.flags)
			}
			if !strings.Contains(in.Human, tt.humanHas) || in.Human == "" {
				t.Errorf("human %q lacks %q", in.Human, tt.humanHas)
			}
		})
	}
}

func TestDecodePersonalSign(t *testing.T) {
	chain := uint64(8453)
	for _, tt := range []struct {
		msg, op, human string
		flags          []string
	}{
		{"0x5369676e20696e20746f206578616d706c652e636f6d", "personal_sign", `Sign the message "Sign in to example.com"`, []string{}},
		{"0x" + strings.Repeat("ab", 32), "personal_sign_raw", "Sign 32 raw bytes", []string{FlagOpaque}},
		{"0x68692e2e2ee280ae", "personal_sign_raw", "not readable text", []string{FlagOpaque}}, // U+202E right-to-left override
	} {
		in, err := Decoder{}.Decode(context.Background(), model.Action{Kind: model.KindEVMPersonalSign, ChainID: &chain, From: signer, Message: tt.msg})
		if err != nil {
			t.Fatal(err)
		}
		if in.Kind != "sign_message" || in.Op != tt.op || !slices.Equal(in.Flags, tt.flags) || !strings.Contains(in.Human, tt.human) {
			t.Errorf("%s: %+v", tt.msg, in)
		}
	}
	if _, err := (Decoder{}).Decode(context.Background(), model.Action{Kind: model.KindEVMPersonalSign, ChainID: &chain, Message: "zz"}); err == nil {
		t.Error("non-hex message decoded")
	}
}

// FuzzTypedData feeds arbitrary typed-data JSON through validation and the
// decoder: either an error or an intent with flags, never a panic.
func FuzzTypedData(f *testing.F) {
	for _, s := range []string{permit2612("1", in10days), daiPermitTD("true", "0"), permitBatchTD("1", maxU160), seaportTD(nftOffer, payMe), mailTD} {
		f.Add(s)
	}
	chain := uint64(8453)
	f.Fuzz(func(t *testing.T, s string) {
		var td model.TypedData
		if json.Unmarshal([]byte(s), &td) != nil {
			return
		}
		in, err := Decoder{Now: func() time.Time { return offNow }}.Decode(context.Background(),
			model.Action{Kind: model.KindEVMTypedData, ChainID: &chain, From: signer, TypedData: &td})
		if err == nil && (in.Flags == nil || in.Human == "" || in.Kind == "") {
			t.Fatalf("incomplete intent %+v", in)
		}
	})
}
