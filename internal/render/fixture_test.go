package render

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/NikhilSetiya/stopbar/internal/decision"
	evmdec "github.com/NikhilSetiya/stopbar/internal/decode/evm"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// The spec fixture's `rendered` is what the real decoder plus this renderer
// produce for its request (no price: the token is unknown), so the fixture
// documents the exact text an approver sees.
func TestFixtureRendering(t *testing.T) {
	b, err := os.ReadFile("../../spec/fixtures/escalation_status.denied.json")
	if err != nil {
		t.Fatal(err)
	}
	var st model.EscalationStatus
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	in, err := evmdec.Decoder{}.Decode(context.Background(), st.Request.Action)
	if err != nil {
		t.Fatal(err)
	}
	if in.PayloadHash, err = decision.PayloadHash(st.Request.Action); err != nil || in.PayloadHash != st.Decision.PayloadHash {
		t.Fatalf("payload hash %s, %v; fixture decision has %s", in.PayloadHash, err, st.Decision.PayloadHash)
	}
	if got := Intent(model.EnrichedRequest{Request: st.Request, Intent: in, PriceStale: true}); got != st.Rendered {
		t.Fatalf("fixture rendered is stale:\n--- got\n%s\n--- fixture\n%s", got, st.Rendered)
	}
}
