package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// keyList collects a repeatable --key flag.
type keyList []string

func (k *keyList) String() string     { return fmt.Sprint(len(*k), " keys") }
func (k *keyList) Set(v string) error { *k = append(*k, v); return nil }

const breakerUsage = "usage: stopbar breaker status --tenant T [--url URL] [--key APPROVER_KEY]\n" +
	"       stopbar breaker reset --tenant T --url URL --key APPROVER_KEY [--key APPROVER_KEY ...]"

// breakerCmd reads or resets a tenant's circuit breaker (CS-124). A reset is a
// vote per approver key: stopbard closes the breaker only once a quorum of
// distinct approver identities has voted. Votes persist, so approvers may run
// it one at a time with their own key; the command fails (the reset is
// refused) while the quorum is not met.
func breakerCmd(args []string) error {
	if len(args) == 0 || (args[0] != "status" && args[0] != "reset") {
		return errors.New(breakerUsage)
	}
	fs := flag.NewFlagSet("breaker "+args[0], flag.ContinueOnError)
	base := fs.String("url", "http://127.0.0.1:7777", "stopbard base URL")
	tenant := fs.String("tenant", "", "tenant whose breaker to read or reset (required)")
	var keys keyList
	fs.Var(&keys, "key", "approver API key (needs the 'approve' scope for the tenant); repeat for each approver")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *tenant == "" || fs.NArg() != 0 || (args[0] == "reset" && len(keys) == 0) || (args[0] == "status" && len(keys) > 1) {
		return errors.New(breakerUsage)
	}
	path := strings.TrimRight(*base, "/") + "/v1/breakers/" + url.PathEscape(*tenant)
	if args[0] == "status" {
		st, _, err := breakerCall(http.MethodGet, path, append(keys, "")[0])
		if err != nil {
			return err
		}
		printBreaker(st)
		return nil
	}
	var st model.BreakerStatus
	for i, k := range keys {
		var code int
		var err error
		if st, code, err = breakerCall(http.MethodPost, path+"/reset", k); err != nil {
			return fmt.Errorf("vote %d of %d: %w", i+1, len(keys), err)
		}
		fmt.Printf("vote %d: HTTP %d, %d of %d approvals\n", i+1, code, len(st.Votes), st.Quorum)
		if !st.Open {
			printBreaker(st)
			return nil
		}
	}
	printBreaker(st)
	return fmt.Errorf("reset refused: %d of %d distinct approvals; the breaker stays open (every request for tenant %q is denied CIRCUIT_OPEN)",
		len(st.Votes), st.Quorum, st.Tenant)
}

// breakerCall makes one call and decodes a BreakerStatus (200 or 202).
func breakerCall(method, u, key string) (model.BreakerStatus, int, error) {
	var st model.BreakerStatus
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return st, 0, err
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return st, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return st, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return st, resp.StatusCode, fmt.Errorf("bad breaker status: %w", err)
	}
	if err := st.Validate(); err != nil {
		return st, resp.StatusCode, fmt.Errorf("bad breaker status: %w", err)
	}
	return st, resp.StatusCode, nil
}

func printBreaker(st model.BreakerStatus) {
	b, _ := json.MarshalIndent(st, "", "  ")
	state := "CLOSED"
	if st.Open {
		state = "OPEN (every request for the tenant is denied CIRCUIT_OPEN)"
	}
	fmt.Printf("breaker %s: %s\n%s\n", st.Tenant, state, b)
}
