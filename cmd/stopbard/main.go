// Command stopbard is the Stopbar policy service / sidecar.
//
// Until authentication lands (CS-103) it only listens on loopback. Without
// -dev-world it runs no engine and /v1/evaluate answers ENGINE_UNAVAILABLE.
// With -dev-world it runs the real engine and policy bundle on stub
// components (internal/devstub) with the real limiter and decision signer.
// With -dev-wallet it is in gatekeeper mode: an allow returns a transaction
// signed by the adapter after it verified the decision token.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/devstub"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/nonce"
	"github.com/NikhilSetiya/stopbar/internal/policy"
	"github.com/NikhilSetiya/stopbar/internal/signer"
	"github.com/NikhilSetiya/stopbar/internal/version"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7777", "address to listen on (loopback only until CS-103 adds auth)")
	showVersion := flag.Bool("version", false, "print version and exit")
	devWorld := flag.String("dev-world", "", "DEV ONLY: run the engine on stub components seeded from this world JSON (corpus setup shape)")
	policies := flag.String("policies", "examples/policies", "policy bundle directory (with -dev-world)")
	devAudit := flag.String("dev-audit", "", "DEV ONLY: append the stub audit chain to this file (default stderr)")
	stateDir := flag.String("state-dir", "", "directory for durable state (limiter.db, nonces.db, adapter-spent.db); default in memory, lost on restart")
	decisionKey := flag.String("decision-key", "", "DEV ONLY (local key provider): Ed25519 decision key file, mode 0600; default an ephemeral key")
	devWallet := flag.String("dev-wallet", "", "DEV ONLY: secp256k1 wallet key file, mode 0600; enables gatekeeper mode (allow returns a signed tx)")
	tenant := flag.String("tenant", "test", "tenant this deployment serves (decision tokens are scoped to it)")
	flag.Parse()
	if *showVersion {
		fmt.Println("stopbard", version.Version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	nonces, err := openStore(*stateDir, "nonces.db")
	if err != nil {
		log.Error("stopbard exiting", "err", err)
		os.Exit(1)
	}
	eval, keys, err := devEngine(devOpts{world: *devWorld, policies: *policies, audit: *devAudit, stateDir: *stateDir,
		decisionKey: *decisionKey, wallet: *devWallet, tenant: *tenant}, log)
	if err != nil {
		log.Error("stopbard exiting", "err", err)
		os.Exit(1)
	}
	if *stateDir == "" {
		log.Warn("no -state-dir: nonces and limiter state are in memory; a restart reopens replay windows and resets caps")
	}
	if err := run(*listen, eval, nonces, keys, log); err != nil {
		log.Error("stopbard exiting", "err", err)
		os.Exit(1)
	}
}

type devOpts struct {
	world, policies, audit, stateDir, decisionKey, wallet, tenant string
}

const (
	devIssuer   = "stopbar:dev"
	devAudience = "signer:dev-local"
)

// devEngine wires the real engine, limiter, policy bundle and decision signer
// to devstub components. With a dev wallet it runs in gatekeeper mode. It
// returns no engine when world is empty. The local key providers (decision
// key, wallet) are dev only, so they refuse to load without -dev-world.
func devEngine(o devOpts, log *slog.Logger) (gateway.Evaluator, func() []decision.JWK, error) {
	if o.world == "" {
		if o.decisionKey != "" || o.wallet != "" {
			return nil, nil, errors.New("-decision-key and -dev-wallet are dev-only local key providers and require -dev-world")
		}
		return nil, nil, nil
	}
	if o.decisionKey != "" && o.decisionKey == o.wallet {
		return nil, nil, errors.New("the decision key and the wallet key must be different files")
	}
	w, err := devstub.LoadWorld(o.world)
	if err != nil {
		return nil, nil, err
	}
	b, err := policy.Load(o.policies)
	if err != nil {
		return nil, nil, err
	}
	var aw io.Writer = os.Stderr
	if o.audit != "" {
		f, err := os.OpenFile(o.audit, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, err
		}
		aw = f // closed at process exit
	}
	var store limiter.Store
	if o.stateDir != "" {
		bs, err := limiter.OpenBolt(filepath.Join(o.stateDir, "limiter.db"))
		if err != nil {
			return nil, nil, err
		}
		store = bs // closed at process exit
	}
	lim, err := limiter.New(limiter.Config{Rules: w.Limits, Store: store})
	if err != nil {
		return nil, nil, err
	}

	var dk ed25519.PrivateKey
	if o.decisionKey != "" {
		if dk, err = decision.LoadKeyFile(o.decisionKey); err != nil {
			return nil, nil, err
		}
	} else {
		_, dk, _ = ed25519.GenerateKey(nil)
		log.Warn("ephemeral decision key: tokens stop verifying when this process exits", "kid", decision.Kid(dk.Public().(ed25519.PublicKey)))
	}
	ring := decision.NewKeyRing(dk)

	e, err := engine.New(engine.Config{
		Decoders:  []engine.Decoder{devstub.Decoder{}},
		Enrichers: []engine.Enricher{w, lim}, // lim supplies velocity
		Policy:    b,
		Limiter:   lim,
		Signer:    &decision.Signer{Keys: ring, Iss: devIssuer, Aud: devAudience},
		Audit:     &devstub.Audit{W: aw},
		Logger:    log,
	})
	if err != nil {
		return nil, nil, err
	}
	var eval gateway.Evaluator = e
	mode := "advisory (allow returns a decision token)"
	if o.wallet != "" {
		keys, err := signer.LoadDevWallet(o.wallet)
		if err != nil {
			return nil, nil, err
		}
		spent, err := openStore(o.stateDir, "adapter-spent.db")
		if err != nil {
			return nil, nil, err
		}
		ad, err := signer.New(&decision.Verifier{Keys: ring.PublicKeys, Iss: devIssuer, Aud: devAudience, Tenant: o.tenant, Spent: spent}, keys)
		if err != nil {
			return nil, nil, err
		}
		eval = &signer.Gatekeeper{Engine: e, Adapter: ad, Logger: log}
		mode = fmt.Sprintf("gatekeeper (allow returns a signed tx; wallets %v)", ad.Addresses())
	}
	log.Warn("DEV STUBS ENABLED: decoder, price/balance enricher and audit are stand-ins; local key providers. Not for production.",
		"world", o.world, "policies", o.policies, "bundle_hash", b.Hash(), "mode", mode, "decision_kid", ring.ActiveKid())
	return eval, ring.JWKS, nil
}

// openStore returns a single-use store (nonces, spent tokens): durable under
// stateDir, in memory otherwise.
func openStore(stateDir, file string) (*nonce.Store, error) {
	if stateDir == "" {
		return nonce.NewMemory(nil), nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	return nonce.OpenBolt(filepath.Join(stateDir, file), nil)
}

func run(addr string, eval gateway.Evaluator, nonces gateway.NonceStore, keys func() []decision.JWK, log *slog.Logger) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           gateway.New(gateway.Config{Evaluator: eval, Nonces: nonces, Keys: keys, Logger: log}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	// The resolved address goes to stdout so callers using :0 can find it.
	fmt.Printf("stopbard %s listening on %s\n", version.Version, ln.Addr())
	log.Info("listening", "addr", ln.Addr().String(), "version", version.Version, "engine", eval != nil)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// requireLoopback refuses to serve an unauthenticated API beyond this host.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid -listen %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing to listen on %q: no authentication yet (CS-103), so only loopback addresses are allowed", addr)
	}
	return nil
}
