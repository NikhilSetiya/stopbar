package evm

import (
	"encoding/hex"
	"math/big"
	"strings"
)

// A minimal Solidity ABI encoder for building test calldata, written
// separately from the decoder so each checks the other.

type val interface{}

type (
	addrV  string
	uintV  struct{ n *big.Int }
	boolV  bool
	bytesV []byte
	arrV   []val // dynamic array T[]
	tupV   []val // tuple (static if every member is static)
)

func u(n int64) uintV     { return uintV{big.NewInt(n)} }
func ub(n *big.Int) uintV { return uintV{n} }
func maxBits(bits uint) *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), bits), big.NewInt(1))
}

func isDynamic(v val) bool {
	switch x := v.(type) {
	case bytesV, arrV:
		return true
	case tupV:
		for _, m := range x {
			if isDynamic(m) {
				return true
			}
		}
	}
	return false
}

func word(n *big.Int) []byte {
	b := make([]byte, 32)
	n.FillBytes(b)
	return b
}

func encodeOne(v val) []byte {
	switch x := v.(type) {
	case addrV:
		b, err := hex.DecodeString(strings.TrimPrefix(string(x), "0x"))
		if err != nil || len(b) != 20 {
			panic("bad test address " + string(x))
		}
		return append(make([]byte, 12), b...)
	case uintV:
		return word(x.n)
	case boolV:
		if x {
			return word(big.NewInt(1))
		}
		return word(big.NewInt(0))
	case bytesV:
		out := word(big.NewInt(int64(len(x))))
		pad := (32 - len(x)%32) % 32
		return append(append(out, x...), make([]byte, pad)...)
	case arrV:
		return append(word(big.NewInt(int64(len(x)))), encodeSeq(x)...)
	case tupV:
		return encodeSeq(x)
	}
	panic("unknown test value")
}

// encodeSeq is the head/tail encoding of a sequence (arguments, a tuple's
// members, or an array's elements).
func encodeSeq(vs []val) []byte {
	headLen := 0
	for _, v := range vs {
		if isDynamic(v) {
			headLen += 32
		} else {
			headLen += len(encodeOne(v))
		}
	}
	var head, tail []byte
	for _, v := range vs {
		if isDynamic(v) {
			head = append(head, word(big.NewInt(int64(headLen+len(tail))))...)
			tail = append(tail, encodeOne(v)...)
		} else {
			head = append(head, encodeOne(v)...)
		}
	}
	return append(head, tail...)
}

// calldata is selector ‖ encoded arguments.
func calldata(sel string, vs ...val) []byte {
	s, err := hex.DecodeString(sel)
	if err != nil {
		panic(err)
	}
	return append(s, encodeSeq(vs)...)
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }
