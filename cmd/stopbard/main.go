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
	"strings"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/decode/evm"
	"github.com/NikhilSetiya/stopbar/internal/decode/toolcall"
	"github.com/NikhilSetiya/stopbar/internal/devstub"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/enrich"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/model"
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
	authKeys := flag.String("auth-keys", "", "API key store (JSON array of `stopbar keygen api-key` records); enables authentication and non-loopback listening")
	ratePerMin := flag.Int("rate-per-min", 0, "per-identity request cap per minute (0: no gateway cap)")
	pendingTTL := flag.Duration("pending-ttl", engine.DefaultPendingTTL, "how long an escalation waits for approve/reject before it expires (deny)")
	coolingOff := flag.Duration("contact-cooling-off", enrich.DefaultCoolingOff, "how long an approved destination-registry addition waits before it counts as known (CS-134)")
	breakerQuorum := flag.Int("breaker-quorum", limiter.DefaultBreakerQuorum, "distinct approver OWNERS needed (M of N, CS-124/151) to reset a tripped circuit breaker; always at least 2, with no -dev-world exception (internal/limiter.New enforces this unconditionally)")
	approvalQuorum := flag.Int("approval-quorum", limiter.DefaultBreakerQuorum, "distinct approver OWNERS needed (M of N, CS-151) to approve an escalation or a destination-registry addition; at least 2 unless -dev-world")
	approversFile := flag.String("approvers", "", "CS-151: approver public-key config (JSON, internal/approval.LoadConfigFile), shared by escalation approve/reject, breaker reset and contact approval — required for each; without it all three are disabled")
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
			"decision-key": decisionKey, "dev-wallet": devWallet, "tenant": tenant, "auth-keys": authKeys,
			"approvers": approversFile,
		}, checkpointEvery, map[string]*int{"rate-per-min": ratePerMin, "breaker-quorum": breakerQuorum, "approval-quorum": approvalQuorum},
			map[string]*time.Duration{"pending-ttl": pendingTTL, "contact-cooling-off": coolingOff}); err != nil {
			log.Error("stopbard config", "err", err)
			os.Exit(1)
		}
	}
	// -breaker-quorum has no -dev-world exception: internal/limiter.New
	// enforces at least 2 unconditionally (CS-124, unchanged by CS-151), so
	// this is just an early, clearer error for the same floor.
	if *breakerQuorum < model.MinBreakerQuorum {
		log.Error("stopbard config", "err", fmt.Sprintf("-breaker-quorum must be at least %d distinct approvers", model.MinBreakerQuorum))
		os.Exit(1)
	}
	// -approval-quorum (CS-151, escalation approve/reject): -dev-world allows
	// a lower quorum (down to 1) for local testing; a production deployment
	// (no -dev-world) never goes below approval.MinQuorumProduction (2).
	if err := approval.ValidateQuorum(*approvalQuorum, *devWorld != ""); err != nil {
		log.Error("stopbard config", "err", err)
		os.Exit(1)
	}
	if err := serve(*listen, *stateDir, devOpts{world: *devWorld, policies: *policies, decisionKey: *decisionKey,
		wallet: *devWallet, tenant: *tenant, checkpointEvery: *checkpointEvery, authKeys: *authKeys, ratePerMin: *ratePerMin,
		breakerQuorum: *breakerQuorum, approvalQuorum: *approvalQuorum, pendingTTL: *pendingTTL, coolingOff: *coolingOff, approversFile: *approversFile}, log); err != nil {
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
func applyConfigFile(path string, strs map[string]*string, checkpointEvery *uint64, ints map[string]*int, durs map[string]*time.Duration) error {
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
		AuthKeys             string `json:"auth_keys"`
		Approvers            string `json:"approvers"`
		AuditCheckpointEvery uint64 `json:"audit_checkpoint_every"`
		RatePerMin           int    `json:"rate_per_min"`
		PendingTTL           string `json:"pending_ttl"`
		ContactCoolingOff    string `json:"contact_cooling_off"` // Go duration, e.g. "24h"
		BreakerQuorum        int    `json:"breaker_quorum"`
		ApprovalQuorum       int    `json:"approval_quorum"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	for name, val := range map[string]string{"listen": c.Listen, "policies": c.Policies, "state-dir": c.StateDir,
		"dev-world": c.DevWorld, "dev-wallet": c.DevWallet, "decision-key": c.DecisionKey, "tenant": c.Tenant, "auth-keys": c.AuthKeys,
		"approvers": c.Approvers} {
		if val != "" && !set[name] {
			*strs[name] = val
		}
	}
	if c.AuditCheckpointEvery != 0 && !set["audit-checkpoint-every"] {
		*checkpointEvery = c.AuditCheckpointEvery
	}
	for name, val := range map[string]int{"rate-per-min": c.RatePerMin, "breaker-quorum": c.BreakerQuorum, "approval-quorum": c.ApprovalQuorum} {
		if val != 0 && !set[name] {
			*ints[name] = val
		}
	}
	for name, val := range map[string]string{"pending-ttl": c.PendingTTL, "contact-cooling-off": c.ContactCoolingOff} {
		if val == "" || set[name] {
			continue
		}
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("config %s: %s: %w", path, strings.ReplaceAll(name, "-", "_"), err)
		}
		*durs[name] = d
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
	var authn gateway.Authenticator
	if o.authKeys != "" {
		ks, err := auth.LoadKeyStore(o.authKeys)
		if err != nil {
			return err
		}
		authn = gateway.BearerAuthenticator{Store: ks}
		log.Info("authentication enabled", "auth_keys", o.authKeys, "rate_per_min", o.ratePerMin)
	}
	if rt.contacts != nil && authn == nil {
		log.Warn("contacts API disabled: it needs -auth-keys (approval is separated by API key)")
	}
	runErr := run(addr, gateway.Config{Evaluator: rt.eval, Nonces: nonces, Keys: rt.keys, Counters: rt.counters, Logger: log,
		Authenticator: authn, Audit: rt.audit, RatePerMin: o.ratePerMin, Approver: rt.approver, Breaker: rt.breaker, Actions: rt.actions,
		Contacts: rt.contacts}, log)
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
	authKeys                                     string
	approversFile                                string
	ratePerMin, breakerQuorum, approvalQuorum    int
	pendingTTL, coolingOff                       time.Duration
	world, policies, decisionKey, wallet, tenant string
	checkpointEvery                              uint64
	db                                           *store.DB
}

// runtime is what serve needs from the wiring.
type runtime struct {
	eval     gateway.Evaluator
	approver gateway.Approver
	actions  gateway.Actions
	breaker  gateway.Breaker
	contacts gateway.Contacts
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
	// CS-151: the configured approver public keys, shared by escalation
	// approve/reject (the engine) and breaker reset (the limiter). Without
	// -approvers both are disabled (Approvers nil): no API key ever
	// substitutes for a signature.
	var approvers *approval.KeySet
	if o.approversFile != "" {
		if approvers, err = approval.LoadConfigFile(o.approversFile); err != nil {
			return runtime{}, fmt.Errorf("-approvers %s: %w", o.approversFile, err)
		}
		log.Info("approver keys loaded (CS-151)", "approvers", o.approversFile, "keys", approvers.Len(),
			"breaker_quorum", o.breakerQuorum, "approval_quorum", o.approvalQuorum)
	} else {
		log.Warn("no -approvers: escalation approve/reject, breaker reset and contact approval are disabled")
	}
	alerts := approval.NewAlerts(log)
	lim, err := limiter.New(limiter.Config{Rules: w.Limits, Store: limStore, BreakerQuorum: o.breakerQuorum, Approvers: approvers, Logger: log})
	if err != nil {
		return runtime{}, err
	}

	// The price/balance enricher: the chain reader (CS-131/132) when the world
	// gives a chain RPC, else the static stub. Either way the limiter follows,
	// supplying velocity. Approval (CS-152) re-runs these enrichers, so when the
	// chain reader is active an approval re-checks live on-chain state.
	var priceBalance engine.Enricher = w
	var stageTimeout time.Duration // 0: engine default (1s), fine for in-memory stubs
	if w.ChainRPC != "" {
		ce, err := enrich.New(enrich.Config{RPCURL: w.ChainRPC, Feeds: w.Feeds,
			MaxSlippage: w.MaxSlippage, RPCTimeout: 3 * time.Second})
		if err != nil {
			return runtime{}, err
		}
		priceBalance = ce
		// Chain reads make several sequential RPC round-trips on a cache miss, so
		// the per-stage budget must allow for them (the 1s default fits only the
		// in-memory stub). Each RPC call is itself bounded above.
		stageTimeout = 10 * time.Second
		log.Info("enricher: reading balances and prices from the chain (CS-131/132)", "rpc", w.ChainRPC, "feeds", len(w.Feeds))
	}
	pending, err := newPendingStore(o.db, lg)
	if err != nil {
		return runtime{}, err
	}
	// The destination registry (CS-133/134) lives in the state file. The
	// world's known_destinations seed it for this tenant, active at once
	// (added if missing, audited); /v1/contacts edits it live, with approval
	// and cooling-off for additions.
	if o.coolingOff < 0 {
		return runtime{}, errors.New("-contact-cooling-off must not be negative")
	}
	reg, err := enrich.OpenRegistry(o.db, lg)
	if err != nil {
		return runtime{}, err
	}
	reg.CoolingOff, reg.Approvers, reg.Quorum = o.coolingOff, approvers, o.approvalQuorum
	if o.coolingOff == 0 {
		log.Warn("-contact-cooling-off 0: an approved destination is known at once, with no window to notice and remove it")
	}
	seeded := 0
	for _, d := range w.KnownDestinations {
		added, err := reg.Seed(o.tenant, d, time.Now())
		if err != nil {
			return runtime{}, err
		}
		if added {
			seeded++
		}
	}
	if seeded > 0 {
		log.Info("destination registry seeded from the dev world", "tenant", o.tenant, "added", seeded)
	}
	// Order matters: the registry sets the destination facts the limiter's
	// unknown-destination caps read, and the limiter reads the priced amount.
	enrichers := []engine.Enricher{priceBalance, reg, lim} // lim supplies velocity and soft-cap flags
	if b.Trust() != nil {
		// Tool-call bundle: session taint from its frozen trust map.
		enrichers = append(enrichers, &policy.SessionTaint{Bundle: b})
	}
	e, err := engine.New(engine.Config{
		Decoders:       []engine.Decoder{evm.Decoder{}, toolcall.Decoder{}},
		Enrichers:      enrichers,
		Policy:         b,
		Limiter:        lim,
		Signer:         &decision.Signer{Keys: ring, Iss: devIssuer, Aud: devAudience},
		Audit:          lg,
		Pending:        pending,
		PendingTTL:     o.pendingTTL,
		StageTimeout:   stageTimeout,
		Logger:         log,
		Approvers:      approvers,
		ApprovalQuorum: o.approvalQuorum,
		Alerts:         alerts,
	})
	if err != nil {
		return runtime{}, err
	}
	var eval gateway.Evaluator = e
	var approver gateway.Approver = e // advisory: an approved allow returns the decision token
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
		gk := &signer.Gatekeeper{Engine: e, Adapter: ad, Logger: log}
		eval, approver = gk, gk
		mode = fmt.Sprintf("gatekeeper (allow returns a signed tx; wallets %v)", ad.Addresses())
	}
	log.Warn("DEV STUBS ENABLED: decoder and price/balance enricher are stand-ins; local key providers. Not for production.",
		"world", o.world, "policies", o.policies, "bundle_hash", b.Hash(), "mode", mode, "decision_kid", ring.ActiveKid())
	counters := func() map[string]uint64 {
		c := e.Counters()
		for k, v := range lim.Counters() { // the breaker trip alert lives here
			c[k] = v
		}
		// CS-151: stopbar_approval_rejects_total, summed across tenant/kind —
		// the per-event breakdown is in the high-severity log line Alerts.Veto
		// emits (tenant, kind, kid, owner), not this flat HTTP counter.
		var rejects uint64
		for _, n := range alerts.Counters() {
			rejects += n
		}
		c["stopbar_approval_rejects_total"] = rejects
		return c
	}
	return runtime{eval: eval, approver: approver, actions: e, breaker: lim, contacts: reg, keys: ring.JWKS, counters: counters, audit: lg, signed: true}, nil
}

func run(addr string, gc gateway.Config, log *slog.Logger) error {
	if err := requireLoopbackUnlessAuth(addr, gc.Authenticator != nil); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           gateway.New(gc),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	// The resolved address goes to stdout so callers using :0 can find it.
	fmt.Printf("stopbard %s listening on %s\n", version.Version, ln.Addr())
	log.Info("listening", "addr", ln.Addr().String(), "version", version.Version, "engine", gc.Evaluator != nil)

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

// pendingStore records escalations and their lifecycle in the state DB
// (CS-152), as JSON keyed by request id. Each write carries its audit record in
// the same bbolt transaction. It survives restart with the rest of state.db.
type pendingStore struct {
	db  *store.DB
	log *audit.Log
}

// v2: records carry the requester's full identity, which an approved token
// binds (decision-token v2). v1 records (key ID only) are never read, so an
// escalation pending across the upgrade cannot be approved; it lapses.
var pendingBucket = []byte("pending_escalations_v2")

func newPendingStore(db *store.DB, log *audit.Log) (*pendingStore, error) {
	if err := db.Bucket(pendingBucket); err != nil {
		return nil, err
	}
	return &pendingStore{db, log}, nil
}

func (p *pendingStore) Put(_ context.Context, e engine.PendingEscalation, rec *model.AuditEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return p.db.Update(func(tx *bolt.Tx) error {
		if rec != nil {
			if err := p.log.AppendTx(tx, *rec); err != nil {
				return err
			}
		}
		return tx.Bucket(pendingBucket).Put([]byte(e.Request.ID), b)
	})
}

func (p *pendingStore) Get(_ context.Context, id string) (engine.PendingEscalation, bool, error) {
	var e engine.PendingEscalation
	var found bool
	err := p.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(pendingBucket).Get([]byte(id))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &e)
	})
	return e, found, err
}

// requireLoopbackUnlessAuth refuses to serve an unauthenticated API beyond this
// host (CS-103): a non-loopback address is allowed only when authentication is
// configured (-auth-keys), so an agent/tenant identity can never be spoofed
// over the network.
func requireLoopbackUnlessAuth(addr string, authEnabled bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid -listen %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		if !authEnabled {
			return fmt.Errorf("refusing to listen on %q without authentication: set -auth-keys to serve a non-loopback address", addr)
		}
	}
	return nil
}
