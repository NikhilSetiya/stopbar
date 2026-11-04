package main

import "testing"

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
