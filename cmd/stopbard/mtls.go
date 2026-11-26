package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
)

// tlsOpts is the mTLS service-mode configuration (CS-103 increment 3, ADR
// 0006): the server certificate and key, the CA that issues client
// certificates, and the SPIFFE ID -> identity map.
type tlsOpts struct{ cert, key, clientCA, identities string }

func (t tlsOpts) set() bool {
	return t.cert != "" || t.key != "" || t.clientCA != "" || t.identities != ""
}

// loadMTLS validates the mTLS configuration and returns the listener's TLS
// config and the authenticator, or nil, nil when mTLS is off. It refuses every
// insecure or ambiguous combination at startup rather than serving: TLS
// without client-certificate authentication (or the reverse), mTLS alongside
// API keys (one identity source per deployment), a group- or world-readable
// server key, and any file that is missing, unreadable, malformed or expired.
func loadMTLS(t tlsOpts, apiKeys bool, now time.Time) (*tls.Config, gateway.Authenticator, error) {
	if !t.set() {
		return nil, nil, nil
	}
	if t.cert == "" || t.key == "" || t.clientCA == "" || t.identities == "" {
		return nil, nil, errors.New("-tls-cert, -tls-key, -tls-client-ca and -mtls-identities must all be set: stopbard serves TLS only with client-certificate authentication")
	}
	if apiKeys {
		return nil, nil, errors.New("-auth-keys and mTLS (-tls-client-ca) are exclusive: a deployment has one identity source")
	}
	fi, err := os.Stat(t.key)
	if err != nil {
		return nil, nil, fmt.Errorf("-tls-key: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, nil, fmt.Errorf("-tls-key %s has mode %o; must be 0600 or stricter", t.key, fi.Mode().Perm())
	}
	cert, err := tls.LoadX509KeyPair(t.cert, t.key)
	if err != nil {
		return nil, nil, fmt.Errorf("-tls-cert/-tls-key: %w", err)
	}
	if now.After(cert.Leaf.NotAfter) || now.Before(cert.Leaf.NotBefore) {
		return nil, nil, fmt.Errorf("-tls-cert %s is not valid now (valid %s to %s)", t.cert, cert.Leaf.NotBefore, cert.Leaf.NotAfter)
	}
	pool, err := auth.LoadCertPool(t.clientCA)
	if err != nil {
		return nil, nil, fmt.Errorf("-tls-client-ca: %w", err)
	}
	cm, err := auth.LoadCertMap(t.identities, pool)
	if err != nil {
		return nil, nil, fmt.Errorf("-mtls-identities: %w", err)
	}
	return gateway.ServerTLSConfig(cert, pool), gateway.MTLSAuthenticator{Map: cm}, nil
}
