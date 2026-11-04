// Command stopbar is the Stopbar CLI (policy test, audit verify, corpus replay).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/signer"
	"github.com/NikhilSetiya/stopbar/internal/store"
	"github.com/NikhilSetiya/stopbar/internal/version"
)

const usage = `usage:
  stopbar version
  stopbar decode-tx <0x raw signed tx>   decode an EIP-1559 tx: recovered sender, every field, payload_hash
  stopbar audit verify --state-dir DIR --keys JWKS.json [--from N] [--to M] [--require-covered [--allow-empty]]
      recompute the audit hash chain and check the signed checkpoints, offline
  stopbar audit export --state-dir DIR [--from N] [--to M]
      print audit records as JSON lines (unverified; run verify first)`

func main() {
	if len(os.Args) < 2 || os.Args[1] == "version" {
		fmt.Println("stopbar", version.Version)
		return
	}
	switch os.Args[1] {
	case "audit":
		if err := auditCmd(os.Args[2:]); err != nil {
			fail(err.Error())
		}
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

func auditCmd(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("audit "+args[0], flag.ContinueOnError)
	stateDir := fs.String("state-dir", "", "stopbard state directory (holds state.db)")
	keysFile := fs.String("keys", "", "decision keys as served at /v1/keys (verify)")
	from := fs.Uint64("from", 1, "first record")
	to := fs.Uint64("to", 0, "last record (0: through the end)")
	requireCovered := fs.Bool("require-covered", false, "fail if any record is after the last signed checkpoint, or the log is empty")
	allowEmpty := fs.Bool("allow-empty", false, "with --require-covered: an empty log is expected (nothing was accepted)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *stateDir == "" {
		return errors.New("--state-dir is required")
	}
	db, err := store.OpenReadOnly(filepath.Join(*stateDir, "state.db"))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	switch args[0] {
	case "export":
		recs, err := audit.Records(db, *from, *to)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		for _, r := range recs {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	case "verify":
		keys, err := loadKeys(*keysFile)
		if err != nil {
			return err
		}
		rep, err := audit.Verify(db, keys, *from, *to)
		if err != nil {
			return fmt.Errorf("audit verify FAILED: %w", err)
		}
		if *requireCovered && ((rep.Records == 0 && !*allowEmpty) || rep.Uncovered > 0) {
			return fmt.Errorf("audit verify FAILED: %d of %d records are not covered by a signed checkpoint", rep.Uncovered, rep.Records)
		}
		if rep.Records == 0 {
			fmt.Println("audit verify OK: empty log (nothing was accepted)")
			return nil
		}
		fmt.Printf("audit verify OK: records %d..%d (%d), %d signed checkpoints, last at %d, %d uncovered, head %s\n",
			rep.From, rep.To, rep.Records, rep.Checkpoints, rep.LastCheckpointSeq, rep.Uncovered, rep.Head)
		return nil
	default:
		return errors.New(usage)
	}
}

// loadKeys reads a /v1/keys document. Each kid is recomputed from its key,
// so a mislabelled entry cannot vouch for a checkpoint.
func loadKeys(path string) (map[string]ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("--keys is required (save GET /v1/keys)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []decision.JWK `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := map[string]ed25519.PublicKey{}
	for _, k := range doc.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || k.Kty != "OKP" || k.Crv != "Ed25519" || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s: key %s is not an Ed25519 OKP key", path, k.Kid)
		}
		pub := ed25519.PublicKey(raw)
		if decision.Kid(pub) != k.Kid {
			return nil, fmt.Errorf("%s: kid %s does not match its key", path, k.Kid)
		}
		out[k.Kid] = pub
	}
	return out, nil
}
