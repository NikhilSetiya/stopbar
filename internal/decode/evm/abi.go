package evm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// args reads Solidity ABI-encoded arguments (the calldata after the 4-byte
// selector). Stdlib only: the decoder decides what the policy sees, so it is
// held to the trusted core's no-dependency rule. Every read is bounds-checked
// and every malformed input is an error, never a guess.
type args []byte

var errShort = errors.New("calldata too short")

// maxLen caps any length or offset read from calldata, so a hostile length
// can never drive an allocation or an overflow.
const maxLen = 1 << 20

func (a args) word(i int) ([]byte, error) {
	off := i * 32
	if i < 0 || off+32 > len(a) || off < 0 {
		return nil, fmt.Errorf("%w: word %d of %d", errShort, i, len(a)/32)
	}
	return a[off : off+32], nil
}

func (a args) uint(i int) (*big.Int, error) {
	w, err := a.word(i)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(w), nil
}

// small reads a word that must fit in an int below maxLen (an offset, a
// length, an enum).
func (a args) small(i int) (int, error) {
	w, err := a.word(i)
	if err != nil {
		return 0, err
	}
	for _, b := range w[:24] {
		if b != 0 {
			return 0, fmt.Errorf("word %d: value too large", i)
		}
	}
	v := binary.BigEndian.Uint64(w[24:])
	if v > maxLen {
		return 0, fmt.Errorf("word %d: value %d too large", i, v)
	}
	return int(v), nil
}

func (a args) address(i int) (string, error) {
	w, err := a.word(i)
	if err != nil {
		return "", err
	}
	for _, b := range w[:12] {
		if b != 0 {
			return "", fmt.Errorf("word %d: address has non-zero high bytes", i)
		}
	}
	return "0x" + hex.EncodeToString(w[12:]), nil
}

func (a args) boolean(i int) (bool, error) {
	v, err := a.small(i)
	if err != nil {
		return false, err
	}
	if v > 1 {
		return false, fmt.Errorf("word %d: bool is %d", i, v)
	}
	return v == 1, nil
}

// tail returns the region a head word at index i points to (an offset
// relative to the start of a).
func (a args) tail(i int) (args, error) {
	off, err := a.small(i)
	if err != nil {
		return nil, err
	}
	if off%32 != 0 || off > len(a) {
		return nil, fmt.Errorf("word %d: bad offset %d", i, off)
	}
	return a[off:], nil
}

// bytesAt reads a dynamic `bytes` whose offset is in head word i.
func (a args) bytesAt(i int) ([]byte, error) {
	t, err := a.tail(i)
	if err != nil {
		return nil, err
	}
	return t.bytesHere()
}

// bytesHere reads a `bytes` laid out at the start of a: length, then data.
func (a args) bytesHere() ([]byte, error) {
	n, err := a.small(0)
	if err != nil {
		return nil, err
	}
	if 32+n > len(a) {
		return nil, fmt.Errorf("%w: bytes of length %d", errShort, n)
	}
	return a[32 : 32+n], nil
}

// array returns the element count and the element region of a dynamic
// array whose offset is in head word i. Elements start right after the
// length word; offsets inside dynamic elements are relative to that start.
func (a args) array(i int) (int, args, error) {
	t, err := a.tail(i)
	if err != nil {
		return 0, nil, err
	}
	n, err := t.small(0)
	if err != nil {
		return 0, nil, err
	}
	if n > 4096 {
		return 0, nil, fmt.Errorf("array of %d elements", n)
	}
	return n, t[32:], nil
}

// bytesArray reads `bytes[]` whose offset is in head word i.
func (a args) bytesArray(i int) ([][]byte, error) {
	n, el, err := a.array(i)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, n)
	for k := range n {
		if out[k], err = el.bytesAt(k); err != nil {
			return nil, fmt.Errorf("element %d: %w", k, err)
		}
	}
	return out, nil
}

// addressArray reads `address[]` whose offset is in head word i.
func (a args) addressArray(i int) ([]string, error) {
	n, el, err := a.array(i)
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for k := range n {
		if out[k], err = el.address(k); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// tupleArray returns each element of a dynamic array of dynamic tuples
// (each element is an offset to its own tuple region).
func (a args) tupleArray(i int) ([]args, error) {
	n, el, err := a.array(i)
	if err != nil {
		return nil, err
	}
	out := make([]args, n)
	for k := range n {
		if out[k], err = el.tail(k); err != nil {
			return nil, fmt.Errorf("element %d: %w", k, err)
		}
	}
	return out, nil
}

func isMax(n *big.Int, bits uint) bool {
	return n.BitLen() >= int(bits)
}
