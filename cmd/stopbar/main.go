// Command stopbar is the Stopbar CLI (policy test, audit verify, corpus replay).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/signer"
	"github.com/NikhilSetiya/stopbar/internal/version"
)

const usage = `usage:
  stopbar version
  stopbar decode-tx <0x raw signed tx>   decode an EIP-1559 tx: recovered sender, every field, payload_hash`

func main() {
	if len(os.Args) < 2 || os.Args[1] == "version" {
		fmt.Println("stopbar", version.Version)
		return
	}
	switch os.Args[1] {
	case "decode-tx":
		if len(os.Args) != 3 {
			fail(usage)
		}
		if err := decodeTx(os.Args[2]); err != nil {
			fail(err.Error())
		}
	default:
		fail(usage)
	}
}

// decodeTx prints what a signed transaction actually does, independently of
// whatever Stopbar said about it: the sender recovered from the signature,
// every field, and the payload_hash those fields bind to.
func decodeTx(raw string) error {
	b, err := hexutil.Decode(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("decode-tx: %w", err)
	}
	tx, err := signer.DecodeRaw(b)
	if err != nil {
		return fmt.Errorf("decode-tx: %w", err)
	}
	a, err := signer.ActionOf(tx)
	if err != nil {
		return fmt.Errorf("decode-tx: %w", err)
	}
	ph, err := decision.PayloadHash(a)
	if err != nil {
		return err
	}
	out := map[string]any{"tx_hash": tx.Hash().Hex(), "payload_hash": ph, "action": a}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}
