package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/NikhilSetiya/stopbar/internal/decision"
)

// keyFileTag marks an approver private-key file. It differs from
// decision's "stopbar-decision-key-ed25519-v1\n" and from the wallet key
// tag (internal/signer), so no file can be loaded as the wrong kind of key
// (spec §5).
const keyFileTag = "stopbar-approver-key-ed25519-v1\n"

// b64 is strict unpadded base64url, the encoding used throughout (key
// files, kid thumbprints, signatures), matching internal/decision.
var b64 = base64.RawURLEncoding.Strict()

// GenerateKey creates a new approver keypair. The private key never leaves
// the caller's process; WriteKeyFile is how it is persisted, and only ever
// to a local file the CLI holds.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// WriteKeyFile writes priv as a tagged approver key file, mode 0600. It
// refuses to overwrite an existing file, so a second keygen can never
// silently discard a key in use.
func WriteKeyFile(path string, priv ed25519.PrivateKey) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("approval: %s already exists; refusing to overwrite a key", path)
	}
	return os.WriteFile(path, []byte(keyFileTag+b64.EncodeToString(priv.Seed())+"\n"), 0o600)
}

// LoadKeyFile reads an approver key written by WriteKeyFile. It refuses a
// file readable by anyone but its owner, and any file that is not a tagged
// approver key — in particular, a decision key file or a wallet key file
// can never be loaded as an approver key.
func LoadKeyFile(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("approval: key file %s has mode %o; must be 0600 or stricter", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rest, ok := strings.CutPrefix(string(b), keyFileTag)
	if !ok {
		return nil, fmt.Errorf("approval: %s is not a Stopbar approver key file", path)
	}
	seed, err := b64.DecodeString(strings.TrimSpace(rest))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("approval: %s: malformed key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Kid is the approver key's lookup identity: the same RFC 7638 JWK
// thumbprint construction internal/decision uses for decision keys, over a
// different key (spec §4.1). Reusing it keeps one thumbprint rule in the
// codebase; it does not make an approver key a decision key — the key
// *files* stay separately tagged, and the *sets* a verifier checks against
// are always distinct.
func Kid(pub ed25519.PublicKey) string { return decision.Kid(pub) }
