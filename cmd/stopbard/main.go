// Command stopbard is the Stopbar policy service / sidecar.
//
// Until authentication lands (CS-103) it only listens on loopback, and until
// the engine lands (CS-104) /v1/evaluate answers ENGINE_UNAVAILABLE: nothing
// it returns can authorise a signature.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/gateway"
	"github.com/NikhilSetiya/stopbar/internal/version"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7777", "address to listen on (loopback only until CS-103 adds auth)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("stopbard", version.Version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*listen, log); err != nil {
		log.Error("stopbard exiting", "err", err)
		os.Exit(1)
	}
}

func run(addr string, log *slog.Logger) error {
	if err := requireLoopback(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           gateway.New(gateway.Config{Logger: log}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	// The resolved address goes to stdout so callers using :0 can find it.
	fmt.Printf("stopbard %s listening on %s\n", version.Version, ln.Addr())
	log.Info("listening", "addr", ln.Addr().String(), "version", version.Version, "engine", "none (CS-104)")

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
