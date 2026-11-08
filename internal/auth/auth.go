// Package auth authenticates a request and carries the authenticated identity
// (CS-103). Identity comes from auth alone — an API key now, mTLS/SPIFFE later —
// never from the request body: the body's claimed tenant and agent must match
// the authenticated identity, or the gateway rejects the request. The identity
// is then recorded in every audit record and (decision-token v2) bound into the
// decision token.
//
// stdlib only: API keys are verified by their SHA-256, never stored in the clear.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

// Errors. ErrUnauthenticated is a missing or unknown credential (→ 401);
// a scope or identity-mismatch is the caller's, handled by the gateway.
var ErrUnauthenticated = errors.New("auth: unauthenticated")

// Method is how a request was authenticated.
type Method string

const (
	MethodAPIKey Method = "api_key"
	MethodMTLS   Method = "mtls"
)

// Identity is who a request is authenticated as. It is the single source of
// truth for the caller; the request body never sets it.
type Identity struct {
	Method  Method   `json:"method"`
	Tenant  string   `json:"tenant"`
	AgentID string   `json:"agent_id,omitempty"`
	Scopes  []string `json:"scopes,omitempty"`
	KeyID   string   `json:"key_id,omitempty"` // api-key record id (later: SPIFFE id)
}

// HasScope reports whether the identity carries scope s.
func (id Identity) HasScope(s string) bool { return slices.Contains(id.Scopes, s) }

type ctxKey struct{}

// WithIdentity attaches the authenticated identity to a context, so the engine
// can record it in the audit body without the body carrying it.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the authenticated identity attached by WithIdentity.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// KeyRecord is a stored API key: the secret's SHA-256, never the secret. It
// matches `stopbar keygen api-key` output and is scoped and rotatable.
type KeyRecord struct {
	ID      string   `json:"id"`
	Tenant  string   `json:"tenant"`
	AgentID string   `json:"agent_id"`
	Scopes  []string `json:"scopes"`
	SHA256  string   `json:"sha256"`
	Revoked bool     `json:"revoked,omitempty"`
}

// KeyStore verifies API keys against hashed records. Rotatable: reload the file
// to add or revoke keys. Immutable after Load.
type KeyStore struct {
	byHash map[string]KeyRecord
}

// LoadKeyStore reads a JSON array of KeyRecords (or JSONL, one per line). Each
// record must carry a 64-hex SHA-256 and a tenant; duplicate hashes are rejected.
func LoadKeyStore(path string) (*KeyStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	recs, err := parseRecords(b)
	if err != nil {
		return nil, fmt.Errorf("auth: %s: %w", path, err)
	}
	ks := &KeyStore{byHash: make(map[string]KeyRecord, len(recs))}
	for i, r := range recs {
		if len(r.SHA256) != 64 || r.Tenant == "" {
			return nil, fmt.Errorf("auth: %s: record %d needs a 64-hex sha256 and a tenant", path, i)
		}
		if _, dup := ks.byHash[r.SHA256]; dup {
			return nil, fmt.Errorf("auth: %s: duplicate key hash %s", path, r.SHA256)
		}
		ks.byHash[strings.ToLower(r.SHA256)] = r
	}
	if len(ks.byHash) == 0 {
		return nil, fmt.Errorf("auth: %s: no keys", path)
	}
	return ks, nil
}

func parseRecords(b []byte) ([]KeyRecord, error) {
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "[") {
		var recs []KeyRecord
		return recs, json.Unmarshal([]byte(trimmed), &recs)
	}
	var recs []KeyRecord // JSONL
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r KeyRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// Verify authenticates a presented secret against the store and returns the
// identity it authenticates as. The secret is matched by its SHA-256 only.
func (ks *KeyStore) Verify(secret string) (Identity, error) {
	if secret == "" {
		return Identity{}, ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(secret))
	rec, ok := ks.byHash[hex.EncodeToString(sum[:])]
	if !ok || rec.Revoked {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Method: MethodAPIKey, Tenant: rec.Tenant, AgentID: rec.AgentID,
		Scopes: slices.Clone(rec.Scopes), KeyID: rec.ID}, nil
}
