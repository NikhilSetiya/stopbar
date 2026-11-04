package main

import (
	"log/slog"
	"strings"
	"testing"
)

func TestRequireLoopback(t *testing.T) {
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
		if err := requireLoopback(addr); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", addr, err, ok)
		}
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
