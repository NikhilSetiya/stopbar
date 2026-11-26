package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"

	"github.com/NikhilSetiya/stopbar/internal/auth"
)

// apiClient makes every call to stopbard. mtlsFlags replaces it when the
// command is given a client certificate or a CA (CS-103 increment 3).
var apiClient = http.DefaultClient

// mtlsFlags registers --cert, --cert-key and --cacert on fs. The returned
// function, called after fs.Parse, points apiClient at an mTLS deployment
// when any of them is set.
func mtlsFlags(fs *flag.FlagSet) func() error {
	cert := fs.String("cert", "", "client certificate PEM, for a stopbard in mTLS mode (its SPIFFE ID is the caller's identity)")
	key := fs.String("cert-key", "", "private key PEM for --cert")
	ca := fs.String("cacert", "", "CA certificate PEM that issued stopbard's server certificate (default: system roots)")
	return func() error {
		if *cert == "" && *key == "" && *ca == "" {
			return nil
		}
		if (*cert == "") != (*key == "") {
			return errors.New("--cert and --cert-key go together")
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if *cert != "" {
			c, err := tls.LoadX509KeyPair(*cert, *key)
			if err != nil {
				return fmt.Errorf("--cert/--cert-key: %w", err)
			}
			// Always present it: Go's default withholds a certificate whose
			// issuer the server does not list, which surfaces as a vague 401.
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }
		}
		if *ca != "" {
			pool, err := auth.LoadCertPool(*ca)
			if err != nil {
				return fmt.Errorf("--cacert: %w", err)
			}
			cfg.RootCAs = pool
		}
		apiClient = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		return nil
	}
}
