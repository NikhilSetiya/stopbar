// Command stopbar is the Stopbar CLI (policy test, audit verify, corpus replay).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
  stopbar keygen decision-key <file>     generate a Stopbar decision key (Ed25519, mode 0600)
  stopbar keygen api-key --tenant T [--agent ID] [--scopes a,b]
      generate an API key: the secret (shown once) and the hashed record to store
  stopbar audit verify --state-dir DIR (--keys JWKS.json | --decision-key FILE) [--from N] [--to M] [--require-covered [--allow-empty]]
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
	case "keygen":
		if err := keygenCmd(os.Args[2:]); err != nil {
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
	decisionKeyFile := fs.String("decision-key", "", "one-shot verify: derive the keys from the Stopbar decision key FILE directly, no running server (single-key deployments)")
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
		keys, err := verifyKeys(*keysFile, *decisionKeyFile)
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

// verifyKeys returns the public keys to verify against, from a saved /v1/keys
// document (--keys) or, for a single-key deployment, derived directly from the
// decision key FILE (--decision-key) so verify needs no running server.
func verifyKeys(keysFile, decisionKeyFile string) (map[string]ed25519.PublicKey, error) {
	if (keysFile == "") == (decisionKeyFile == "") {
		return nil, errors.New("exactly one of --keys (saved /v1/keys) or --decision-key (the key file) is required")
	}
	if decisionKeyFile != "" {
		priv, err := decision.LoadKeyFile(decisionKeyFile)
		if err != nil {
			return nil, err
		}
		pub := priv.Public().(ed25519.PublicKey)
		return map[string]ed25519.PublicKey{decision.Kid(pub): pub}, nil
	}
	return loadKeys(keysFile)
}

// keygenCmd generates the keys a deployment needs: the Ed25519 decision key
// (for signing decision tokens and audit checkpoints) and API keys (for the
// auth CS-103 adds). The decision key is written in Stopbar's tagged file
// format; an API key's secret is shown once and only its hash is stored.
func keygenCmd(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "decision-key":
		if len(args) != 2 {
			return errors.New("usage: stopbar keygen decision-key <file>")
		}
		path := args[1]
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("keygen: %s already exists; refusing to overwrite a key", path)
		}
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		if err := decision.WriteKeyFile(path, priv); err != nil {
			return err
		}
		fmt.Printf("wrote decision key %s (kid %s, mode 0600)\n", path, decision.Kid(pub))
		return nil
	case "api-key":
		fs := flag.NewFlagSet("keygen api-key", flag.ContinueOnError)
		tenant := fs.String("tenant", "", "tenant the key is scoped to (required)")
		agent := fs.String("agent", "", "agent id the key authenticates as (optional)")
		scopes := fs.String("scopes", "evaluate", "comma-separated scopes")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *tenant == "" {
			return errors.New("keygen api-key: --tenant is required")
		}
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		secret := "stopbar_sk_" + base64.RawURLEncoding.EncodeToString(raw)
		sum := sha256.Sum256([]byte(secret))
		rec := map[string]any{
			"id":          "ak_" + hex.EncodeToString(sum[:4]),
			"tenant":      *tenant,
			"agent_id":    *agent,
			"scopes":      strings.Split(*scopes, ","),
			"sha256":      hex.EncodeToString(sum[:]),
			"created_utc": time.Now().UTC().Format(time.RFC3339),
		}
		recJSON, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "SECRET (shown once — give it to the client, it is NOT recoverable from the record):\n  %s\n\n", secret)
		fmt.Println("# API key record — store this server-side (hashed, scoped, rotatable):")
		fmt.Println(string(recJSON))
		return nil
	default:
		return errors.New(usage)
	}
}
