package evm

import (
	"context"
	"testing"
)

// BenchmarkDecode: an ERC-20 transfer, and a Safe execTransaction that
// delegatecalls MultiSend with a batch of two transfers (the decoder
// recurses into both) (CS-197).
func BenchmarkDecode(b *testing.B) {
	const zero = "0x0000000000000000000000000000000000000000"
	transfer := calldata(selTransfer, addrV(friend), u(1000))
	batch := append(msEntry(0, token, 0, transfer), msEntry(0, token2, 0, transfer)...)
	safeTx := calldata(selExecTransaction, addrV(multiSnd), u(0), bytesV(calldata(selMultiSend, bytesV(batch))), u(1),
		u(0), u(0), u(0), addrV(zero), addrV(zero), bytesV([]byte{1, 2, 3}))
	for _, tc := range []struct {
		name string
		to   string
		data []byte
	}{{"transfer", token, transfer}, {"safe_multisend", safe, safeTx}} {
		a := tx(tc.to, "0", tc.data)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := (Decoder{}).Decode(context.Background(), a); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
