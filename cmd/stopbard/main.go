// Command stopbard is the Stopbar policy service / sidecar.
//
// Until authentication lands (CS-103) it only listens on loopback. Without
// -dev-world it runs no engine and /v1/evaluate answers ENGINE_UNAVAILABLE.
// With -dev-world it runs the real engine and policy bundle on stub
// components (internal/devstub) and the real limiter: decisions are real,
// tokens are deliberately unverifiable, so nothing it returns can authorise
// a signature.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/devstub"
	"github.com/NikhilSetiya/stopbar/internal/engine"
	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/limiter"
	"github.com/NikhilSetiya/stopbar/internal/policy"
	"github.com/NikhilSetiya/stopbar/internal/version"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7777", "address to listen on (loopback only until CS-103 adds auth)")
	showVersion := flag.Bool("version", false, "print version and exit")
	devWorld := flag.String("dev-world", "", "DEV ONLY: run the engine on stub components seeded from this world JSON (corpus setup shape)")
	policies := flag.String("policies", "examples/policies", "policy bundle directory (with -dev-world)")
	devAudit := flag.String("dev-audit", "", "DEV ONLY: append the stub audit chain to this file (default stderr)")
	limiterDB := flag.String("limiter-db", "", "persist limiter state in this bbolt file (default: in memory, reset on restart)")
	flag.Parse()
	if *showVersion {
		fmt.Println("stopbard", version.Version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	eval, err := devEngine(*devWorld, *policies, *devAudit, *limiterDB, log)
	if err != nil {
		log.Error("stopbard exiting", "err", err)
		os.Exit(1)
	}
	if err := run(*listen, eval, log); err != nil {
		log.Error("stopbard exiting", "err", err)
		os.Exit(1)
	}
}

// devEngine wires the real engine and policy bundle to devstub components.
// It returns nil (no engine) when world is empty.
func devEngine(world, policies, auditPath, limiterDB string, log *slog.Logger) (gateway.Evaluator, error) {
	if world == "" {
		return nil, nil
	}
	w, err := devstub.LoadWorld(world)
	if err != nil {
		return nil, err
	}
	b, err := policy.Load(policies)
	if err != nil {
		return nil, err
	}
	var aw io.Writer = os.Stderr
	if auditPath != "" {
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		aw = f // closed at process exit
	}
	var store limiter.Store
	if limiterDB != "" {
		bs, err := limiter.OpenBolt(limiterDB)
		if err != nil {
			return nil, err
		}
		store = bs // closed at process exit
	}
	lim, err := limiter.New(limiter.Config{Rules: w.Limits, Store: store})
	if err != nil {
		return nil, err
	}
	e, err := engine.New(engine.Config{
		Decoders:  []engine.Decoder{devstub.Decoder{}},
		Enrichers: []engine.Enricher{w, lim}, // lim supplies velocity
		Policy:    b,
		Limiter:   lim,
		Signer:    devstub.UnsignedSigner{},
		Audit:     &devstub.Audit{W: aw},
		Logger:    log,
	})
	if err != nil {
		return nil, err
	}
	log.Warn("DEV STUBS ENABLED: decoder, price/balance enricher, signer and audit are stand-ins; tokens are unsigned. Not for production.",
		"world", world, "policies", policies, "bundle_hash", b.Hash())
	return e, nil
}

func run(addr string, eval gateway.Evaluator, log *slog.Logger) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           gateway.New(gateway.Config{Evaluator: eval, Logger: log}),
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
