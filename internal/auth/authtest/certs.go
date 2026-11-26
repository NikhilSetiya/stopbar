// Package authtest mints throwaway X.509 certificates for mTLS tests (CS-103).
// Keys are generated per test run and never written outside t.TempDir().
package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA returns a fresh self-signed CA.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	return &CA{Cert: sign(t, tmpl, tmpl, &key.PublicKey, key), key: key}
}

// Pool is a CertPool holding just this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Leaf describes a certificate to issue. Zero NotAfter means 24h from now;
// nil ExtKeyUsage means client and server auth.
type Leaf struct {
	URIs        []string
	DNSNames    []string
	IPs         []net.IP
	NotAfter    time.Time
	IsCA        bool
	ExtKeyUsage []x509.ExtKeyUsage
}

// Issue signs a leaf and returns it as a tls.Certificate (Leaf set).
func (ca *CA) Issue(t testing.TB, l Leaf) tls.Certificate {
	t.Helper()
	key := genKey(t)
	if l.NotAfter.IsZero() {
		l.NotAfter = time.Now().Add(24 * time.Hour)
	}
	if l.ExtKeyUsage == nil {
		l.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: l.NotAfter,
		DNSNames: l.DNSNames, IPAddresses: l.IPs, ExtKeyUsage: l.ExtKeyUsage,
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: l.IsCA,
	}
	for _, s := range l.URIs {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	c := sign(t, tmpl, ca.Cert, &key.PublicKey, ca.key)
	return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
}

// WritePEM writes the CA certificate to dir/name and returns the path.
func (ca *CA) WritePEM(t testing.TB, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	write(t, p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o644)
	return p
}

// WriteKeyPair writes c's certificate and key (mode 0600) under dir and
// returns their paths.
func WriteKeyPair(t testing.TB, c tls.Certificate, dir, name string) (certPath, keyPath string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	write(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o644)
	write(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	return certPath, keyPath
}

func write(t testing.TB, p string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
}

func genKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func sign(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
