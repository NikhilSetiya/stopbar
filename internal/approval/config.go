package approval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
)

// Key is one configured approver: the public key a signature is checked
// against, the tenant it may approve for, and an optional binding to a
// requester identity (AgentID) used by the self-approval check (spec §7).
// ID is an operator-assigned label for logs and audit records; it is never
// used to look a key up — Kid, recomputed from Public, is (spec §5).
type Key struct {
	ID      string
	Tenant  string
	AgentID string // "" unless this approver is also bound to a requester identity
	Public  ed25519.PublicKey
	Kid     string
}

// KeySet is the configured approver keys, indexed by Kid so a mislabelled
// ID can never borrow another key's identity.
type KeySet struct {
	byKid map[string]Key
}

// NewKeySet builds a set from keys, recomputing each Kid from its Public
// key (callers MUST NOT set Kid themselves) and rejecting a duplicate key.
func NewKeySet(keys []Key) (*KeySet, error) {
	byKid := make(map[string]Key, len(keys))
	for _, k := range keys {
		if len(k.Public) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("approval: key %q: not an Ed25519 public key", k.ID)
		}
		if k.Tenant == "" {
			return nil, fmt.Errorf("approval: key %q: tenant is required", k.ID)
		}
		k.Kid = Kid(k.Public)
		if _, dup := byKid[k.Kid]; dup {
			return nil, fmt.Errorf("approval: key %q: duplicate key (kid %s already configured)", k.ID, k.Kid)
		}
		byKid[k.Kid] = k
	}
	return &KeySet{byKid: byKid}, nil
}

// Lookup finds a configured key by its wire kid. The bool is false for an
// unconfigured kid (UNKNOWN_KEY at verification).
func (s *KeySet) Lookup(kid string) (Key, bool) {
	if s == nil {
		return Key{}, false
	}
	k, ok := s.byKid[kid]
	return k, ok
}

// Len is the number of distinct configured keys.
func (s *KeySet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byKid)
}

// configEntry is one approver in the on-disk JSON config (spec §5):
//
//	{"approvers": [{"id": "alice", "tenant": "acme", "public_key": "<b64url>"}]}
type configEntry struct {
	ID        string `json:"id"`
	Tenant    string `json:"tenant"`
	AgentID   string `json:"agent_id,omitempty"`
	PublicKey string `json:"public_key"`
}

type configFile struct {
	Approvers []configEntry `json:"approvers"`
}

// LoadConfigFile reads the approver public-key configuration stopbard is
// started with (a config file, or a flag the caller has already merged into
// the same shape). Every entry needs a non-empty id, tenant and a 32-byte
// Ed25519 public key; the set rejects a duplicate key (by kid) across any
// two entries, even for different ids or tenants, since that would make the
// wrong tenant's approver set accept the same signature.
func LoadConfigFile(path string) (*KeySet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(b)
}

// ParseConfig parses the JSON config document b into a KeySet (exported so
// a flag-supplied document, not only a file, can go through the same path).
func ParseConfig(b []byte) (*KeySet, error) {
	var cf configFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("approval: malformed approver config: %w", err)
	}
	if len(cf.Approvers) == 0 {
		return nil, fmt.Errorf("approval: approver config has no approvers")
	}
	keys := make([]Key, 0, len(cf.Approvers))
	for i, e := range cf.Approvers {
		if e.ID == "" {
			return nil, fmt.Errorf("approval: approver config entry %d: id is required", i)
		}
		if e.Tenant == "" {
			return nil, fmt.Errorf("approval: approver %q: tenant is required", e.ID)
		}
		pub, err := b64.DecodeString(e.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("approval: approver %q: public_key must be a base64url-encoded Ed25519 public key", e.ID)
		}
		keys = append(keys, Key{ID: e.ID, Tenant: e.Tenant, AgentID: e.AgentID, Public: ed25519.PublicKey(pub)})
	}
	return NewKeySet(keys)
}
