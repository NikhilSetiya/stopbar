package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikhilSetiya/stopbar/examples/policies"
	"github.com/NikhilSetiya/stopbar/internal/devstub"
	"github.com/NikhilSetiya/stopbar/internal/signer"
)

// initListen is where a generated stopbard listens: loopback, always. A
// non-loopback address is an operator's explicit edit, never a default.
const initListen = "127.0.0.1:7777"

// Base Chainlink USD feeds with their documented heartbeats, as used by the
// live and testnet demos (research/walletagent/demo_{live,testnet}.py).
var initChains = map[string]map[string]any{
	"base": {
		"chain_rpc": "https://mainnet.base.org",
		"feeds": map[string]any{
			"native": map[string]any{"address": "0x71041dddad3595f9ced3dccfbe3d1f4b0a16bb70", "max_age_sec": 3600},
			"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": map[string]any{"address": "0x7e860098f58bbfc8648a4311b374b1d669a2bc6b", "max_age_sec": 86400}, // USDC
		},
	},
	"base-sepolia": {
		"chain_rpc": "https://sepolia.base.org",
		"feeds": map[string]any{
			"native": map[string]any{"address": "0x4aDC67696bA383F43DD60A9e78F2C97FbbFc7cb1", "max_age_sec": 86400},
		},
	},
	// dev: static prices and balances (internal/devstub), no network. A 1 ETH
	// balance keeps the starter pack's 20%-of-balance escalation below the
	// default $5,000/h wallet cap, so an approved escalation can execute.
	"dev": {
		"balances":   map[string]string{"ETH": "1", "USDC": "1000"},
		"prices_usd": map[string]string{"ETH": "3500", "USDC": "1"},
		"tokens":     map[string]any{"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": map[string]any{"symbol": "USDC", "decimals": 6}},
	},
}

// initCmd is `stopbar init` (CS-195, FR-DX-1/3): one directory holding
// everything a protected agent wallet needs, wired so stopbard starts secure
// (loopback, auth on, 2-of-2 signed approvals, gatekeeper mode) from one
// config file. Secrets are 0600; the API key secret is printed once and never
// written. Existing files are never overwritten without --force, and an
// existing state.db (the audit log) is never touched at all.
func initCmd(args []string) error {
	fset := flag.NewFlagSet("init", flag.ContinueOnError)
	persona := fset.String("persona", "agent-wallet", "starter persona (agent-wallet)")
	dir := fset.String("dir", "stopbar", "directory to write into")
	tenant := fset.String("tenant", "demo", "tenant this deployment serves")
	agent := fset.String("agent", "wallet-agent", "agent id the API key authenticates as")
	chain := fset.String("chain", "dev", "price/balance source: dev (static, offline) | base | base-sepolia (read from the chain)")
	rpc := fset.String("rpc", "", "JSON-RPC URL for --chain base|base-sepolia (default: the chain's public RPC)")
	force := fset.Bool("force", false, "overwrite existing generated files (never state/state.db)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 0 {
		return errors.New("usage: stopbar init [--persona agent-wallet] [--dir DIR] [--tenant T] [--agent ID] [--chain dev|base|base-sepolia] [--rpc URL] [--force]")
	}
	if *persona != "agent-wallet" {
		return fmt.Errorf("init: unknown persona %q (available: agent-wallet)", *persona)
	}
	src, ok := initChains[*chain]
	if !ok {
		return fmt.Errorf("init: unknown --chain %q (dev, base, base-sepolia)", *chain)
	}
	if *tenant == "" || *agent == "" {
		return errors.New("init: --tenant and --agent must not be empty")
	}
	world := map[string]any{"limits": devstub.DefaultLimits, "known_destinations": []string{}}
	for k, v := range src {
		world[k] = v
	}
	if *rpc != "" {
		if *chain == "dev" {
			return errors.New("init: --rpc needs --chain base or base-sepolia")
		}
		world["chain_rpc"] = *rpc
	}

	root, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	p := func(name string) string { return filepath.Join(root, name) }
	stateDir := p("state")
	if _, err := os.Stat(filepath.Join(stateDir, "state.db")); err == nil {
		return fmt.Errorf("init: %s exists: it holds the audit log signed with the current decision key; move it aside first (--force never touches it)", filepath.Join(stateDir, "state.db"))
	}
	bundle, err := fs.ReadDir(policies.FS, ".")
	if err != nil {
		return err
	}
	targets := []string{p("stopbard.json"), p("world.json"), p("decision.key"), p("wallet.key"), p("api-keys.json"),
		p("approvers.json"), p("approver-1.key"), p("approver-2.key")}
	for _, e := range bundle {
		targets = append(targets, filepath.Join(p("policies"), e.Name()))
	}
	var exist []string
	for _, t := range targets {
		if _, err := os.Lstat(t); err == nil {
			exist = append(exist, t)
		}
	}
	if len(exist) > 0 && !*force {
		return fmt.Errorf("init: refusing to overwrite existing files (use --force):\n  %s", strings.Join(exist, "\n  "))
	}
	for _, t := range exist { // --force: remove first, so every file is written fresh at its own mode
		if err := os.Remove(t); err != nil {
			return err
		}
	}
	for _, d := range []string{root, stateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(p("policies"), 0o755); err != nil {
		return err
	}

	for _, e := range bundle {
		b, err := policies.FS.ReadFile(e.Name())
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(p("policies"), e.Name()), b, 0o644); err != nil {
			return err
		}
	}
	kid, err := writeDecisionKey(p("decision.key"))
	if err != nil {
		return err
	}
	wallet, err := signer.GenerateDevWallet(p("wallet.key"))
	if err != nil {
		return err
	}
	secret, rec, err := newAPIKey(*tenant, *agent, []string{"evaluate"})
	if err != nil {
		return err
	}
	if err := writeJSON(p("api-keys.json"), []any{rec}); err != nil {
		return err
	}
	// Two approvers, each its own owner (distinct from the agent), so a
	// quorum of 2 needs both signatures and the agent can approve nothing.
	var approvers []map[string]any
	for i := 1; i <= 2; i++ {
		id := fmt.Sprintf("approver-%d", i)
		pub, err := writeApproverKey(p(id + ".key"))
		if err != nil {
			return err
		}
		approvers = append(approvers, map[string]any{"id": id, "tenant": *tenant, "owner": map[string]string{"agent_id": id},
			"public_key": base64.RawURLEncoding.EncodeToString(pub)})
	}
	if err := writeJSON(p("approvers.json"), map[string]any{"approvers": approvers}); err != nil {
		return err
	}
	if err := writeJSON(p("world.json"), world); err != nil {
		return err
	}
	if err := writeJSON(p("stopbard.json"), map[string]any{
		"listen": initListen, "tenant": *tenant, "policies": p("policies"), "state_dir": stateDir,
		"dev_world": p("world.json"), "dev_wallet": p("wallet.key"), "decision_key": p("decision.key"),
		"auth_keys": p("api-keys.json"), "approvers": p("approvers.json"),
		"approval_quorum": 2, "breaker_quorum": 2, "rate_per_min": 600,
	}); err != nil {
		return err
	}

	url := "http://" + initListen
	fmt.Printf(`stopbar init: persona agent-wallet in %[1]s (tenant %[2]s, agent %[3]s, prices: %[4]s)

  stopbard.json        stopbard config: loopback %[5]s, auth on, gatekeeper mode, 2-of-2 signed approvals
  policies/            agent-wallet starter policy pack
  world.json           caps (limits) and the price/balance source; edit known_destinations to allowlist
  decision.key         decision signing key, kid %[6]s (0600)
  wallet.key           gatekeeper wallet %[7]s: stopbard signs for it, the agent never holds it (0600)
  api-keys.json        the agent's API key record (hashed; scope evaluate) (0600)
  approvers.json       public halves of the two approver keys
  approver-1.key       approver private keys (0600): give each to a different person
  approver-2.key
  state/               durable state and the audit log

AGENT API KEY (shown once, stored nowhere; save it now):
  %[8]s

Next:
  1. Start stopbard:
       stopbard -config %[1]s/stopbard.json
  2. Point the SDK at it (pip install "stopbar[approver]" or npm install stopbar); every
     evm_tx must be from the gatekeeper wallet %[7]s:
       export STOPBAR_URL=%[9]s STOPBAR_KEY=%[8]s STOPBAR_TENANT=%[2]s
       sb = stopbar.Client(os.environ["STOPBAR_URL"], api_key=os.environ["STOPBAR_KEY"], tenant="%[2]s", agent_id="%[3]s")
  3. Approve an escalation (HTTP 202 gives its request_id): each approver signs; the first
     reports "escalation not executed (HTTP 202)" until the second reaches quorum:
       stopbar approve <request_id> --approver-key %[1]s/approver-1.key --url %[9]s
       stopbar approve <request_id> --approver-key %[1]s/approver-2.key --url %[9]s
  4. After stopping stopbard, verify the audit log offline:
       stopbar audit verify --state-dir %[1]s/state --decision-key %[1]s/decision.key --require-covered
`, root, *tenant, *agent, *chain, initListen, kid, wallet.Hex(), secret, url)
	return nil
}

// writeJSON writes v as indented JSON, mode 0600.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
