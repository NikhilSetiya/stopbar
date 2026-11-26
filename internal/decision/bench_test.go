package decision

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

func benchRequest(b *testing.B) model.ActionRequest {
	raw, err := os.ReadFile("../../spec/fixtures/action_request.evm_tx.json")
	if err != nil {
		b.Fatal(err)
	}
	var r model.ActionRequest
	if err := json.Unmarshal(raw, &r); err != nil {
		b.Fatal(err)
	}
	return r
}

// BenchmarkPayloadHash: sha256 of the JCS-canonical action (CS-197).
func BenchmarkPayloadHash(b *testing.B) {
	a := benchRequest(b).Action
	b.ReportAllocs()
	for b.Loop() {
		if _, err := PayloadHash(a); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSign: one v2 decision token, Ed25519 over JCS claims (CS-197).
func BenchmarkSign(b *testing.B) {
	_, k, _ := ed25519.GenerateKey(nil)
	s := &Signer{Keys: NewKeyRing(k), Iss: "stopbar:bench", Aud: "signer:bench"}
	r := benchRequest(b)
	ph, err := PayloadHash(r.Action)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	d := model.Decision{RequestID: r.ID, Outcome: model.Allow, PayloadHash: ph,
		PolicyBundleHash: "sha256:" + strings.Repeat("a", 64), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	id := auth.Identity{Method: auth.MethodAPIKey, Tenant: r.Tenant, AgentID: r.Actor.AgentID, KeyID: "ak_bench", Scopes: []string{"evaluate"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := s.Sign(context.Background(), id, r, d); err != nil {
			b.Fatal(err)
		}
	}
}
