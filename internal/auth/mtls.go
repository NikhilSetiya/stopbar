package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// mTLS / SPIFFE client identity (CS-103 increment 3, ADR 0006). The TLS
// handshake proves the client holds the key of a certificate chaining to the
// operator's client CA; Identify re-verifies that chain (so the mapping is
// sound on its own, not only behind a correctly configured listener), takes the
// certificate's single SPIFFE ID URI SAN, and maps it to a tenant, agent and
// scopes from operator configuration. A certificate never names its own
// tenant or scopes: an unmapped SPIFFE ID authenticates as nobody.

// CertIdentity maps one SPIFFE ID to the identity it authenticates as.
type CertIdentity struct {
	SPIFFEID string   `json:"spiffe_id"`
	Tenant   string   `json:"tenant"`
	AgentID  string   `json:"agent_id"`
	Scopes   []string `json:"scopes"`
}

// CertMap verifies client certificates against the client CA and maps their
// SPIFFE IDs to identities. Immutable after Load.
type CertMap struct {
	roots *x509.CertPool
	byID  map[string]CertIdentity
}

// LoadCertPool reads a PEM file of CA certificates. It refuses a file with no
// certificate or with anything that does not parse, so a typo cannot leave a
// listener trusting nothing (or, worse, the system roots).
func LoadCertPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	n := 0
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("auth: %s: unexpected PEM block %q", path, blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("auth: %s: %w", path, err)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 || strings.TrimSpace(string(b)) != "" {
		return nil, fmt.Errorf("auth: %s: want one or more PEM certificates and nothing else", path)
	}
	return pool, nil
}

// LoadCertMap reads a JSON array (or JSONL) of CertIdentity records and binds
// them to the client CA pool. Each needs a well-formed SPIFFE ID and a tenant;
// duplicate IDs are rejected.
func LoadCertMap(path string, roots *x509.CertPool) (*CertMap, error) {
	if roots == nil {
		return nil, fmt.Errorf("auth: %s: no client CA", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	recs, err := parseRecords[CertIdentity](b)
	if err != nil {
		return nil, fmt.Errorf("auth: %s: %w", path, err)
	}
	m := &CertMap{roots: roots, byID: make(map[string]CertIdentity, len(recs))}
	for i, r := range recs {
		if !ValidSPIFFEID(r.SPIFFEID) || r.Tenant == "" {
			return nil, fmt.Errorf("auth: %s: record %d needs a valid spiffe_id (spiffe://<trust-domain>/<path>) and a tenant", path, i)
		}
		if _, dup := m.byID[r.SPIFFEID]; dup {
			return nil, fmt.Errorf("auth: %s: duplicate spiffe_id %s", path, r.SPIFFEID)
		}
		m.byID[r.SPIFFEID] = r
	}
	if len(m.byID) == 0 {
		return nil, fmt.Errorf("auth: %s: no identities", path)
	}
	return m, nil
}

// Identify authenticates a client certificate chain (leaf first, as TLS
// presents it) and returns the identity its SPIFFE ID maps to. Every failure
// wraps ErrUnauthenticated: no certificate, a chain that does not verify
// against the client CA at now (expired, wrong CA, not for client auth), a CA
// leaf, not exactly one URI SAN, a SAN that is not a SPIFFE ID, or an
// unmapped ID.
func (m *CertMap) Identify(chain []*x509.Certificate, now time.Time) (Identity, error) {
	if len(chain) == 0 {
		return Identity{}, fmt.Errorf("%w: no client certificate", ErrUnauthenticated)
	}
	leaf, inter := chain[0], x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: m.roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if leaf.IsCA { // X.509-SVID: a leaf SVID is never a CA
		return Identity{}, fmt.Errorf("%w: client certificate is a CA", ErrUnauthenticated)
	}
	if len(leaf.URIs) != 1 { // X.509-SVID: exactly one URI SAN, so the identity is unambiguous
		return Identity{}, fmt.Errorf("%w: client certificate has %d URI SANs, want exactly one SPIFFE ID", ErrUnauthenticated, len(leaf.URIs))
	}
	id := leaf.URIs[0].String()
	if !ValidSPIFFEID(id) {
		return Identity{}, fmt.Errorf("%w: URI SAN %q is not a SPIFFE ID", ErrUnauthenticated, id)
	}
	rec, ok := m.byID[id]
	if !ok {
		return Identity{}, fmt.Errorf("%w: SPIFFE ID %s is not mapped", ErrUnauthenticated, id)
	}
	return Identity{Method: MethodMTLS, Tenant: rec.Tenant, AgentID: rec.AgentID,
		Scopes: slices.Clone(rec.Scopes), KeyID: id}, nil
}

// ValidSPIFFEID reports whether s is a SPIFFE ID in canonical form:
// spiffe://<trust-domain>/<path>, the trust domain [a-z0-9._-]+, each path
// segment non-empty, [A-Za-z0-9._-]+ and not "." or "..". No port, userinfo,
// query, fragment or percent-encoding, so one identity has one spelling and
// map lookups are exact.
func ValidSPIFFEID(s string) bool {
	rest, ok := strings.CutPrefix(s, "spiffe://")
	if !ok {
		return false
	}
	td, path, _ := strings.Cut(rest, "/")
	if td == "" || !allIn(td, "abcdefghijklmnopqrstuvwxyz0123456789.-_") {
		return false
	}
	if path == "" {
		return false // a bare trust domain names no workload
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." ||
			!allIn(seg, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_") {
			return false
		}
	}
	return true
}

func allIn(s, set string) bool {
	for _, r := range s {
		if !strings.ContainsRune(set, r) {
			return false
		}
	}
	return true
}
