package canon

import (
	"os"
	"testing"
)

// BenchmarkTransform canonicalises the spec's EVM request fixture (CS-197).
func BenchmarkTransform(b *testing.B) {
	in, err := os.ReadFile("../../spec/fixtures/action_request.evm_tx.json")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(in)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Transform(in); err != nil {
			b.Fatal(err)
		}
	}
}
