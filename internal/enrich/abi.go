package enrich

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// The enricher needs only a handful of fixed-shape, read-only calls. Like the
// decoder (internal/decode/evm), it is stdlib-only and so cannot compute
// keccak-256; the selectors below are hard-coded with their canonical
// signatures and cross-checked against keccak in internal/signer
// (TestEnrichSelectorsMatchKeccak), so none of the hex is taken on trust.
const (
	selBalanceOf       = "70a08231" // balanceOf(address) -> uint256
	selDecimals        = "313ce567" // decimals() -> uint8
	selSymbol          = "95d89b41" // symbol() -> string (some old tokens: bytes32)
	selLatestRoundData = "feaf968c" // latestRoundData() -> (uint80,int256,uint256,uint256,uint80)
)

// Signatures maps each selector to its canonical signature, for the keccak
// cross-check in internal/signer.
var Signatures = map[string]string{
	selBalanceOf:       "balanceOf(address)",
	selDecimals:        "decimals()",
	selSymbol:          "symbol()",
	selLatestRoundData: "latestRoundData()",
}

// mustSel decodes a 4-byte selector constant (compile-time-fixed hex).
func mustSel(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		panic("enrich: bad selector constant " + s)
	}
	return b
}

// encodeAddressCall builds calldata for fn(address): selector + the address
// left-padded to 32 bytes.
func encodeAddressCall(sel, addr string) ([]byte, error) {
	a, err := hexToBytes(addr)
	if err != nil {
		return nil, fmt.Errorf("bad address %q: %w", addr, err)
	}
	if len(a) != 20 {
		return nil, fmt.Errorf("address %q is %d bytes, want 20", addr, len(a))
	}
	out := make([]byte, 0, 4+32)
	out = append(out, mustSel(sel)...)
	out = append(out, make([]byte, 12)...) // left-pad address to 32 bytes
	return append(out, a...), nil
}

// encodeCall builds calldata for a no-argument call such as decimals().
func encodeCall(sel string) []byte { return mustSel(sel) }

// decodeUint reads the first 32-byte word of a return value as an unsigned
// integer (balanceOf, decimals, a feed's updatedAt).
func decodeUint(ret []byte) (*big.Int, error) {
	if len(ret) < 32 {
		return nil, fmt.Errorf("return is %d bytes, want ≥32", len(ret))
	}
	return new(big.Int).SetBytes(ret[:32]), nil
}

// maxSymbolBytes bounds the symbol() return we decode; anything longer is
// cut (the rendering caps it far shorter anyway).
const maxSymbolBytes = 256

// decodeString reads an ABI-encoded string return (offset, length, bytes),
// or, for old tokens that return bytes32 (e.g. MKR), the zero-padded bytes.
func decodeString(ret []byte) (string, error) {
	if len(ret) == 32 {
		return strings.TrimRight(string(ret), "\x00"), nil
	}
	off, err := word(ret, 0)
	if err != nil {
		return "", err
	}
	if !off.IsInt64() || off.Int64() > int64(len(ret)-32) || off.Int64() < 0 {
		return "", fmt.Errorf("string offset %s out of range", off)
	}
	o := int(off.Int64())
	n := new(big.Int).SetBytes(ret[o : o+32])
	if !n.IsInt64() || n.Int64() > int64(len(ret)-o-32) {
		return "", fmt.Errorf("string length %s out of range", n)
	}
	b := ret[o+32 : o+32+int(n.Int64())]
	if len(b) > maxSymbolBytes {
		b = b[:maxSymbolBytes]
	}
	return string(b), nil
}

// word returns the i-th 32-byte word of a return value as an unsigned integer.
func word(ret []byte, i int) (*big.Int, error) {
	off := i * 32
	if len(ret) < off+32 {
		return nil, fmt.Errorf("return is %d bytes, want ≥%d", len(ret), off+32)
	}
	return new(big.Int).SetBytes(ret[off : off+32]), nil
}

// signedWord returns the i-th 32-byte word as a two's-complement signed integer
// (Chainlink's latestRoundData answer is int256).
func signedWord(ret []byte, i int) (*big.Int, error) {
	u, err := word(ret, i)
	if err != nil {
		return nil, err
	}
	if ret[i*32]&0x80 != 0 { // top bit set: negative
		u.Sub(u, new(big.Int).Lsh(big.NewInt(1), 256))
	}
	return u, nil
}

// ---- hex helpers ----

func bytesToHex(b []byte) string { return hex.EncodeToString(b) }

func hexToBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func hexToInt(s string) (*big.Int, error) {
	b, err := hexToBytes(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
