package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SHA256Prefix tags every digest so the algorithm is explicit on the wire.
const SHA256Prefix = "sha256:"

// Digest returns "sha256:<hex>" of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return SHA256Prefix + hex.EncodeToString(sum[:])
}

// HashJSON returns the sha256 digest of the RFC 8785 canonical form of v.
// Two semantically identical JSON values always hash identically, regardless
// of key order or whitespace.
func HashJSON(v any) (string, error) {
	c, err := Marshal(v)
	if err != nil {
		return "", err
	}
	return Digest(c), nil
}

// GenesisHash is the prev_hash of the first audit record.
var GenesisHash = SHA256Prefix + strings.Repeat("0", 64)

// recordPreimage is the exact structure hashed for an audit record.
// See spec/audit-hash-v1.md. Using a canonical JSON object (rather than raw
// byte concatenation) removes any field-boundary ambiguity.
type recordPreimage struct {
	V        int    `json:"v"`
	Seq      uint64 `json:"seq"`
	TS       string `json:"ts"`
	Type     string `json:"type"`
	Body     any    `json:"body"`
	PrevHash string `json:"prev_hash"`
}

// RecordHash computes an audit record hash per spec/audit-hash-v1.md:
// sha256(JCS({"v":1,"seq":…,"ts":…,"type":…,"body":…,"prev_hash":…})).
func RecordHash(seq uint64, ts, typ string, body any, prevHash string) (string, error) {
	return HashJSON(recordPreimage{V: 1, Seq: seq, TS: ts, Type: typ, Body: body, PrevHash: prevHash})
}
