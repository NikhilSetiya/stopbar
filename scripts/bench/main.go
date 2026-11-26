// Command bench is the sidecar load harness for NFR-1/NFR-2 (CS-197,
// docs/benchmarks.md). It starts a real stopbard in the configuration a
// sidecar runs (-dev-world engine, -auth-keys, gatekeeper signing with a
// -dev-wallet, a persistent -state-dir so every bbolt commit is fsynced) and
// drives /v1/evaluate open loop at a constant rate: requests are sent on a
// fixed schedule whether or not earlier ones have answered, and latency is
// measured from each request's scheduled time, so a stall shows up in the
// tail instead of being hidden by coordinated omission.
//
// The mix is allow / escalate / deny shapes from the corpus. Every request
// gets a fresh nonce and issued_at (as scripts/corpus_template.py does). A
// response whose HTTP status is not the expected outcome counts as an error.
//
//	go run ./scripts/bench -stopbard ./stopbard -rate 1000 -duration 60s
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	from     = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" // Anvil test account 0 (public test key, never funded)
	anvilKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	token    = "0x6666666666666666666666666666666666666666" // LOBSTAR (corpus fixture)
	known    = "0x4444444444444444444444444444444444444444"
	agent    = "defi-agent"
	tenant   = "test"
)

// world is the corpus-style setup: CS-2026-0002's balances and prices, with
// caps sized so a run of allows never reaches them (the limiter still
// reserves and commits every allow, so its cost is measured).
var world = map[string]any{
	"known_destinations": []string{known},
	"balances":           map[string]string{"LOBSTAR": "52430000", "ETH": "100"},
	"prices_usd":         map[string]string{"ETH": "3500", "LOBSTAR": "0.00477"},
	"tokens":             map[string]any{token: map[string]any{"symbol": "LOBSTAR", "decimals": 18}},
	"limits": []map[string]any{
		{"scope": "wallet", "window": "tx", "max_usd": "10000", "max_pct_of_balance": "0.5"},
		{"scope": "wallet", "window": "1h", "max_usd": "100000000", "max_count": 100000000},
		{"scope": "tenant", "window": "1h", "max_usd": "1000000000", "circuit_breaker": true},
	},
}

func transfer(to string, wholeTokens int64) string {
	amt := new(big.Int).Mul(big.NewInt(wholeTokens), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	return fmt.Sprintf("0xa9059cbb%064s%064x", strings.TrimPrefix(to, "0x"), amt)
}

// shapes: outcome -> (expected HTTP status, action.to, calldata, gas limit).
type shape struct {
	outcome string
	status  int
	to      string
	data    string
	gas     string
}

var shapes = map[string]shape{
	// 1,000 LOBSTAR (~$4.77) to a known destination: policy allows, caps hold.
	"allow": {"allow", 200, token, transfer(known, 1000), "100000"},
	// CS-2026-0002: 100% of the balance to a known destination -> large-share-of-balance.
	"escalate": {"escalate", 202, token, transfer(known, 52430000), "100000"},
	// CS-2026-0010: Safe execTransaction with operation DELEGATECALL to an unknown contract.
	"deny": {"deny", 403, token, "0x6a7612020000000000000000000000009f30000000000000000000000000000000000c210000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000044a9059cbc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "300000"},
}

func body(s shape, n int) []byte {
	nb := make([]byte, 18)
	_, _ = rand.Read(nb)
	b, _ := json.Marshal(map[string]any{
		"id": fmt.Sprintf("bench_%d", n), "tenant": tenant, "nonce": base64.RawURLEncoding.EncodeToString(nb),
		"issued_at": time.Now().UTC().Format(time.RFC3339), "ttl_seconds": 60, "actor": map[string]string{"agent_id": agent},
		"action": map[string]any{"kind": "evm_tx", "chain_id": 8453, "from": from, "to": s.to, "value_wei": "0", "data": s.data,
			"tx_type": 2, "tx_nonce": fmt.Sprint(n), "gas_limit": s.gas, "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000"},
		"provenance": map[string]any{"labels": []string{"trusted_user"}},
	})
	return b
}

type result struct {
	lat     time.Duration
	outcome string
	err     string
}

func main() {
	stopbard := flag.String("stopbard", "", "path to the stopbard binary (required)")
	policies := flag.String("policies", "examples/policies", "policy bundle directory")
	rate := flag.Int("rate", 1000, "requests per second (open loop)")
	duration := flag.Duration("duration", 60*time.Second, "measured duration")
	warmup := flag.Duration("warmup", 5*time.Second, "unmeasured warm-up at the same rate")
	mix := flag.String("mix", "allow=8,escalate=1,deny=1", "request mix by weight")
	keep := flag.String("state-dir", "", "keep state, logs and keys here (default: a temporary directory, removed)")
	flag.Parse()
	if *stopbard == "" || *rate <= 0 {
		flag.Usage()
		os.Exit(2)
	}
	var order []shape
	for _, kv := range strings.Split(*mix, ",") {
		name, w, _ := strings.Cut(kv, "=")
		s, ok := shapes[name]
		var n int
		if _, err := fmt.Sscan(w, &n); !ok || err != nil || n < 0 {
			fail("bad -mix entry %q", kv)
		}
		for range n {
			order = append(order, s)
		}
	}
	if len(order) == 0 {
		fail("empty -mix")
	}

	dir := *keep
	if dir == "" {
		d, err := os.MkdirTemp("", "stopbar-bench-")
		check(err)
		dir = d
	}
	check(os.MkdirAll(dir, 0o700))
	addr, secret, proc := start(*stopbard, *policies, dir)

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 4096, MaxConnsPerHost: 0}}
	url := "http://" + addr + "/v1/evaluate"
	total := int((*warmup + *duration).Seconds() * float64(*rate))
	skip := int(warmup.Seconds() * float64(*rate))
	results := make([]result, total)
	var inflight, maxInflight atomic.Int64
	var wg sync.WaitGroup
	interval := time.Second / time.Duration(*rate)
	fmt.Printf("stopbard %s (gatekeeper, auth on, state %s)\n%d rps for %s after %s warm-up, mix %s\n",
		addr, filepath.Join(dir, "state"), *rate, *duration, *warmup, *mix)
	start := time.Now()
	for i := range total {
		at := start.Add(time.Duration(i) * interval)
		time.Sleep(time.Until(at))
		s := order[i%len(order)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := inflight.Add(1); ; {
				if m := maxInflight.Load(); n <= m || maxInflight.CompareAndSwap(m, n) {
					break
				}
			}
			defer inflight.Add(-1)
			req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body(s, i)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+secret)
			r := result{outcome: s.outcome}
			resp, err := client.Do(req)
			if err != nil {
				r.err = err.Error()
			} else {
				var d struct {
					Outcome  string `json:"outcome"`
					SignedTx string `json:"signed_tx"`
					Code     string `json:"code"` // gateway error
					Reasons  []struct {
						Code string `json:"code"`
					} `json:"reasons"`
				}
				derr := json.NewDecoder(resp.Body).Decode(&d)
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				switch {
				case derr != nil:
					r.err = "bad body: " + derr.Error()
				case resp.StatusCode != s.status || d.Outcome != s.outcome:
					r.err = fmt.Sprintf("HTTP %d %s %s%v, want %d %s", resp.StatusCode, d.Outcome, d.Code, d.Reasons, s.status, s.outcome)
				case s.outcome == "allow" && d.SignedTx == "":
					r.err = "allow without signed_tx"
				}
			}
			r.lat = time.Since(at) // from the scheduled send time: open loop
			results[i] = r
		}()
	}
	sendDone := time.Since(start)
	wg.Wait()
	failed := report(results[skip:], *rate, sendDone, *duration+*warmup, maxInflight.Load())
	_ = proc.Process.Signal(os.Interrupt)
	if err := proc.Wait(); err != nil { // a clean SIGINT shutdown exits 0
		fmt.Println("stopbard did not shut down cleanly:", err)
		failed = true
	}
	if failed {
		if logs, err := os.ReadFile(filepath.Join(dir, "stopbard.log")); err == nil {
			lines := strings.Split(strings.TrimSpace(string(logs)), "\n")
			fmt.Println("stopbard log (last 20 lines):\n" + strings.Join(lines[max(0, len(lines)-20):], "\n"))
		}
	}
	if *keep == "" {
		_ = os.RemoveAll(dir)
	}
	if failed {
		os.Exit(1)
	}
}

// report prints the latency distribution and returns true if any request failed.
func report(rs []result, rate int, sendDone, planned time.Duration, maxInflight int64) bool {
	lats := make([]time.Duration, 0, len(rs))
	byOutcome := map[string]int{}
	errs := map[string]int{}
	nerr := 0
	for _, r := range rs {
		lats = append(lats, r.lat)
		byOutcome[r.outcome]++
		if r.err != "" {
			nerr++
			errs[r.err]++
		}
	}
	slices.Sort(lats)
	q := func(p float64) time.Duration { return lats[min(len(lats)-1, int(p*float64(len(lats))))] }
	ms := func(d time.Duration) string { return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000) }
	fmt.Printf("host: %s/%s, %d CPUs, %s\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
	fmt.Printf("requests: %d measured (%v), schedule kept: sent %s of planned %s, max in flight %d\n",
		len(rs), byOutcome, sendDone.Round(time.Millisecond), planned, maxInflight)
	fmt.Printf("latency: p50 %s  p90 %s  p99 %s  p99.9 %s  max %s\n", ms(q(.50)), ms(q(.90)), ms(q(.99)), ms(q(.999)), ms(lats[len(lats)-1]))
	// Where the tail comes from: seconds (since the end of warm-up) whose
	// slowest request took over 100 ms.
	var slow []string
	for s := 0; s*rate < len(rs); s++ {
		var worst time.Duration
		for _, r := range rs[s*rate : min(len(rs), (s+1)*rate)] {
			worst = max(worst, r.lat)
		}
		if worst > 100*time.Millisecond {
			slow = append(slow, fmt.Sprintf("%ds:%s", s, ms(worst)))
		}
	}
	fmt.Printf("seconds with max > 100ms: %d %v\n", len(slow), slow)
	fmt.Printf("errors: %d (%.3f%%)\n", nerr, 100*float64(nerr)/float64(len(rs)))
	for e, n := range errs {
		fmt.Printf("  %d x %s\n", n, e)
	}
	return nerr > 0
}

// start writes the world, wallet and API key into dir and starts stopbard.
func start(bin, policies, dir string) (addr, secret string, cmd *exec.Cmd) {
	w, err := json.Marshal(world)
	check(err)
	check(os.WriteFile(filepath.Join(dir, "world.json"), w, 0o600))
	check(os.WriteFile(filepath.Join(dir, "wallet"), []byte("stopbar-dev-wallet-secp256k1-v1\n"+anvilKey+"\n"), 0o600))
	sb := make([]byte, 16)
	_, _ = rand.Read(sb)
	secret = "bench-" + hex.EncodeToString(sb)
	sum := sha256.Sum256([]byte(secret))
	keys, err := json.Marshal([]map[string]any{{"id": "ak_bench", "tenant": tenant, "agent_id": agent,
		"scopes": []string{"evaluate"}, "sha256": hex.EncodeToString(sum[:])}})
	check(err)
	check(os.WriteFile(filepath.Join(dir, "api-keys.json"), keys, 0o600))
	logf, err := os.Create(filepath.Join(dir, "stopbard.log"))
	check(err)
	cmd = exec.Command(bin, "-listen", "127.0.0.1:0", "-dev-world", filepath.Join(dir, "world.json"),
		"-dev-wallet", filepath.Join(dir, "wallet"), "-auth-keys", filepath.Join(dir, "api-keys.json"),
		"-state-dir", filepath.Join(dir, "state"), "-policies", policies)
	cmd.Stderr = logf
	out, err := cmd.StdoutPipe()
	check(err)
	check(cmd.Start())
	line, _ := bufio.NewReader(out).ReadString('\n')
	_, a, ok := strings.Cut(strings.TrimSpace(line), "listening on ")
	if !ok {
		_ = cmd.Process.Kill()
		logs, _ := os.ReadFile(logf.Name())
		fail("stopbard did not start: %q\n%s", line, logs)
	}
	return a, secret, cmd
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "bench: "+f+"\n", a...)
	os.Exit(1)
}
