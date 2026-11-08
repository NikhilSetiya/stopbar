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
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/decode/evm"
	"github.com/NikhilSetiya/stopbar/internal/decode/toolcall"
	"github.com/NikhilSetiya/stopbar/internal/devstub"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/nonce"
	"github.com/NikhilSetiya/stopbar/internal/policy"
	"github.com/NikhilSetiya/stopbar/internal/signer"
	"github.com/NikhilSetiya/stopbar/internal/store"
	"github.com/NikhilSetiya/stopbar/internal/version"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7777", "address to listen on (loopback only until CS-103 adds auth)")
	showVersion := flag.Bool("version", false, "print version and exit")
	devWorld := flag.String("dev-world", "", "DEV ONLY: run the engine on stub components seeded from this world JSON (corpus setup shape)")
	policies := flag.String("policies", "examples/policies", "policy bundle directory (with -dev-world)")
	stateDir := flag.String("state-dir", "", "directory for the durable state file (state.db: limiter, nonces, spent tokens, audit log); default a temporary file, lost on exit")
	checkpointEvery := flag.Uint64("audit-checkpoint-every", 1000, "sign an audit checkpoint every N records (and always at shutdown)")
	decisionKey := flag.String("decision-key", "", "DEV ONLY (local key provider): Ed25519 decision key file, mode 0600; default an ephemeral key")
	devWallet := flag.String("dev-wallet", "", "DEV ONLY: secp256k1 wallet key file, mode 0600; enables gatekeeper mode (allow returns a signed tx)")
	tenant := flag.String("tenant", "test", "tenant this deployment serves (decision tokens are scoped to it)")
	configPath := flag.String("config", "", "config file (JSON); its fields set any flag not also given on the command line")
	flag.Parse()
	if *showVersion {
		fmt.Println("stopbard", version.Version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if *configPath != "" {
		if err := applyConfigFile(*configPath, map[string]*string{
			"listen": listen, "dev-world": devWorld, "policies": policies, "state-dir": stateDir,
			"decision-key": decisionKey, "dev-wallet": devWallet, "tenant": tenant,
		}, checkpointEvery); err != nil {
			log.Error("stopbard config", "err", err)
			os.Exit(1)
		}
	}
	if err := serve(*listen, *stateDir, devOpts{world: *devWorld, policies: *policies, decisionKey: *decisionKey,
		wallet: *devWallet, tenant: *tenant, checkpointEvery: *checkpointEvery}, log); err != nil {
		log.Error("stopbard exiting", "err", err)
		os.Exit(1)
	}
}

// applyConfigFile reads a JSON config and fills any flag not given on the
// command line (explicit flags win). A thin first config surface: the fields
// map to the existing flags, so a demo or deployment starts from one file
// instead of a flag soup. It still selects dev-mode components when they are
// named — a production config needs auth, a real key provider and real
// enrichers (none of which exist yet).
func applyConfigFile(path string, strs map[string]*string, checkpointEvery *uint64) error {
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c struct {
		Listen               string `json:"listen"`
		Policies             string `json:"policies"`
		StateDir             string `json:"state_dir"`
		DevWorld             string `json:"dev_world"`
		DevWallet            string `json:"dev_wallet"`
		DecisionKey          string `json:"decision_key"`
		Tenant               string `json:"tenant"`
		AuditCheckpointEvery uint64 `json:"audit_checkpoint_every"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	for name, val := range map[string]string{"listen": c.Listen, "policies": c.Policies, "state-dir": c.StateDir,
		"dev-world": c.DevWorld, "dev-wallet": c.DevWallet, "decision-key": c.DecisionKey, "tenant": c.Tenant} {
		if val != "" && !set[name] {
			*strs[name] = val
		}
	}
	if c.AuditCheckpointEvery != 0 && !set["audit-checkpoint-every"] {
		*checkpointEvery = c.AuditCheckpointEvery
	}
	return nil
}

// serve opens the state file, wires everything, serves until a signal, then
// signs a final audit checkpoint and closes the state file.
func serve(addr, stateDir string, o devOpts, log *slog.Logger) error {
	var db *store.DB
	var err error
	if stateDir != "" {
		db, err = store.Open(filepath.Join(stateDir, "state.db"))
	} else {
		db, err = store.OpenTemp()
		log.Warn("no -state-dir: state is in a temporary file; a restart reopens replay windows, resets caps and loses the audit log")
	}
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	o.db = db
	rt, err := devEngine(o, log)
	if err != nil {
		return err
	}
	if rt.audit == nil { // no engine: still record every accepted request
		if rt.audit, err = audit.New(audit.Config{DB: db}); err != nil {
			return err
		}
	}
	nonces, err := nonce.Open(db, "nonces_v1", rt.audit, nil)
	if err != nil {
		return err
	}
	runErr := run(addr, rt.eval, nonces, rt.keys, rt.counters, log)
	if rt.signed {
		if err := rt.audit.Checkpoint(); err != nil {
			log.Error("final audit checkpoint failed", "severity", "high", "err", err)
		} else {
			log.Info("final audit checkpoint signed")
		}
	}
	return runErr
}

type devOpts struct {
	world, policies, decisionKey, wallet, tenant string
	checkpointEvery                              uint64
	db                                           *store.DB
}

// runtime is what serve needs from the wiring.
type runtime struct {
	eval     gateway.Evaluator
	keys     func() []decision.JWK
	counters func() map[string]uint64
	audit    *audit.Log
	signed   bool // audit checkpoints are signed (dev engine with a decision key)
}

const (
	devIssuer   = "stopbar:dev"
	devAudience = "signer:dev-local"
)

// devEngine wires the real engine, limiter, policy bundle and decision signer
// to devstub components. With a dev wallet it runs in gatekeeper mode. It
// returns no engine when world is empty. The local key providers (decision
// key, wallet) are dev only, so they refuse to load without -dev-world.
func devEngine(o devOpts, log *slog.Logger) (runtime, error) {
	if o.world == "" {
		if o.decisionKey != "" || o.wallet != "" {
			return runtime{}, errors.New("-decision-key and -dev-wallet are dev-only local key providers and require -dev-world")
		}
		return runtime{}, nil
	}
	if o.decisionKey != "" && o.decisionKey == o.wallet {
		return runtime{}, errors.New("the decision key and the wallet key must be different files")
	}
	w, err := devstub.LoadWorld(o.world)
	if err != nil {
		return runtime{}, err
	}
	b, err := policy.Load(o.policies)
	if err != nil {
		return runtime{}, err
	}
	var dk ed25519.PrivateKey
	if o.decisionKey != "" {
		if dk, err = decision.LoadKeyFile(o.decisionKey); err != nil {
			return runtime{}, err
		}
	} else {
		_, dk, _ = ed25519.GenerateKey(nil)
		log.Warn("ephemeral decision key: tokens and audit checkpoints stop verifying unless /v1/keys is saved", "kid", decision.Kid(dk.Public().(ed25519.PublicKey)))
	}
	ring := decision.NewKeyRing(dk)
	lg, err := audit.New(audit.Config{DB: o.db, Signer: ring, CheckpointEvery: o.checkpointEvery})
	if err != nil {
		return runtime{}, err
	}
	limStore, err := limiter.NewBoltStore(o.db, lg)
	if err != nil {
		return runtime{}, err
	}
	lim, err := limiter.New(limiter.Config{Rules: w.Limits, Store: limStore})
	if err != nil {
		return runtime{}, err
	}

	enrichers := []engine.Enricher{w, lim} // lim supplies velocity
	if b.Trust() != nil {
		// Tool-call bundle: session taint from its frozen trust map.
		enrichers = append(enrichers, &policy.SessionTaint{Bundle: b})
	}
	e, err := engine.New(engine.Config{
		Decoders:  []engine.Decoder{evm.Decoder{}, toolcall.Decoder{}},
		Enrichers: enrichers,
		Policy:    b,
		Limiter:   lim,
		Signer:    &decision.Signer{Keys: ring, Iss: devIssuer, Aud: devAudience},
		Audit:     lg,
		Logger:    log,
	})
	if err != nil {
		return runtime{}, err
	}
	var eval gateway.Evaluator = e
	mode := "advisory (allow returns a decision token)"
	if o.wallet != "" {
		keys, err := signer.LoadDevWallet(o.wallet)
		if err != nil {
			return runtime{}, err
		}
		spent, err := nonce.Open(o.db, "adapter_spent_v1", nil, nil)
		if err != nil {
			return runtime{}, err
		}
		// Dev mode only (this whole function requires -dev-world): the corpus
		// signs with Anvil's public account 0.
		ad, err := signer.New(&decision.Verifier{Keys: ring.PublicKeys, Iss: devIssuer, Aud: devAudience, Tenant: o.tenant, Spent: spent}, keys,
			signer.Options{AllowWellKnownTestKeys: true})
		if err != nil {
			return runtime{}, err
		}
		eval = &signer.Gatekeeper{Engine: e, Adapter: ad, Logger: log}
		mode = fmt.Sprintf("gatekeeper (allow returns a signed tx; wallets %v)", ad.Addresses())
	}
	log.Warn("DEV STUBS ENABLED: decoder and price/balance enricher are stand-ins; local key providers. Not for production.",
		"world", o.world, "policies", o.policies, "bundle_hash", b.Hash(), "mode", mode, "decision_kid", ring.ActiveKid())
	return runtime{eval: eval, keys: ring.JWKS, counters: e.Counters, audit: lg, signed: true}, nil
}

func run(addr string, eval gateway.Evaluator, nonces gateway.NonceStore, keys func() []decision.JWK, counters func() map[string]uint64, log *slog.Logger) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           gateway.New(gateway.Config{Evaluator: eval, Nonces: nonces, Keys: keys, Counters: counters, Logger: log}),
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
