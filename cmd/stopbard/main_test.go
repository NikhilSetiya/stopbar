package main

import (
	"log/slog"
	"strings"
	"testing"
)

func TestRequireLoopbackUnlessAuth(t *testing.T) {
	// Without auth, only loopback is allowed.
	for addr, ok := range map[string]bool{
		"127.0.0.1:7777": true,
		"localhost:7777": true,
		"[::1]:7777":     true,
		"127.0.0.1:0":    true,
		":7777":          false, // all interfaces
		"0.0.0.0:7777":   false,
		"[::]:7777":      false,
		"10.0.0.5:7777":  false,
		"example.com:80": false,
		"127.0.0.1":      false, // no port
	} {
		if err := requireLoopbackUnlessAuth(addr, false); (err == nil) != ok {
			t.Errorf("no auth, %s: err=%v, want ok=%v", addr, err, ok)
		}
	}
	// With auth, a non-loopback address is allowed; a malformed one still isn't.
	if err := requireLoopbackUnlessAuth("0.0.0.0:7777", true); err != nil {
		t.Errorf("auth on, 0.0.0.0:7777 should be allowed: %v", err)
	}
	if err := requireLoopbackUnlessAuth("127.0.0.1", true); err == nil {
		t.Error("auth on, a port-less address should still be rejected")
	}
}

func TestLocalKeyProvidersAreDevOnly(t *testing.T) {
	for name, o := range map[string]devOpts{
		"decision key without -dev-world": {decisionKey: "k"},
		"wallet without -dev-world":       {wallet: "w"},
	} {
		if _, err := devEngine(o, slog.New(slog.DiscardHandler)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := devEngine(devOpts{world: "x.json", decisionKey: "same", wallet: "same"}, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "different files") {
		t.Errorf("same file for decision and wallet key: %v", err)
	}
}
