package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// keyList collects a repeatable flag (approver key files, for a reset).
type keyList []string

func (k *keyList) String() string     { return fmt.Sprint(len(*k), " keys") }
func (k *keyList) Set(v string) error { *k = append(*k, v); return nil }

const breakerUsage = "usage: stopbar breaker status --tenant T [--url URL] [--key API_KEY]\n" +
	"       stopbar breaker reset --tenant T --url URL --approver-key FILE [--approver-key FILE ...] [--key API_KEY]"

// breakerCmd reads or resets a tenant's circuit breaker (CS-124/151). A
// reset is a signed vote per approver key: stopbard closes the breaker only
// once a quorum of distinct approver OWNERS has signed. Votes persist, so
// approvers may run it one at a time with their own key file; the command
// fails (the reset is refused) while the quorum is not met. --key, if
// given, is an optional API key for the HTTP call itself — never what
// authorizes the reset, which is the signature (CS-151).
func breakerCmd(args []string) error {
	if len(args) == 0 || (args[0] != "status" && args[0] != "reset") {
		return errors.New(breakerUsage)
	}
	fs := flag.NewFlagSet("breaker "+args[0], flag.ContinueOnError)
	base := fs.String("url", "http://127.0.0.1:7777", "stopbard base URL")
	tenant := fs.String("tenant", "", "tenant whose breaker to read or reset (required)")
	key := fs.String("key", "", "API key for the HTTP call itself (optional)")
	var approverKeys keyList
	fs.Var(&approverKeys, "approver-key", "local approver private key file; repeat once per approver, for a reset")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *tenant == "" || fs.NArg() != 0 || (args[0] == "reset" && len(approverKeys) == 0) || (args[0] == "status" && len(approverKeys) > 0) {
		return errors.New(breakerUsage)
	}
	path := strings.TrimRight(*base, "/") + "/v1/breakers/" + url.PathEscape(*tenant)
	if args[0] == "status" {
		st, _, err := breakerCall(http.MethodGet, path, nil, *key)
		if err != nil {
			return err
		}
		printBreaker(st)
		return nil
	}
	var st model.BreakerStatus
	for i, keyFile := range approverKeys {
		priv, err := approval.LoadKeyFile(keyFile)
		if err != nil {
			return fmt.Errorf("vote %d of %d: %w", i+1, len(approverKeys), err)
		}
		// Re-fetch the current trip on every vote: an earlier vote in this
		// same run may have changed nothing about it, but the trip could
		// have been reset by someone else between votes.
		cur, _, err := breakerCall(http.MethodGet, path, nil, *key)
		if err != nil {
			return fmt.Errorf("vote %d of %d: %w", i+1, len(approverKeys), err)
		}
		sig, err := approval.SignBreakerReset(priv, approval.BreakerResetObject{
			Tenant: *tenant, TripRequestID: cur.TripRequestID, Decision: approval.ResetDecision,
			Expiry: time.Now().Add(50 * time.Minute).Unix(),
		})
		if err != nil {
			return fmt.Errorf("vote %d of %d: %w", i+1, len(approverKeys), err)
		}
		body, err := json.Marshal(sig)
		if err != nil {
			return fmt.Errorf("vote %d of %d: %w", i+1, len(approverKeys), err)
		}
		var code int
		if st, code, err = breakerCall(http.MethodPost, path+"/reset", body, *key); err != nil {
			return fmt.Errorf("vote %d of %d: %w", i+1, len(approverKeys), err)
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

// breakerCall makes one call and decodes a BreakerStatus (200 or 202). body,
// when non-nil, is a signed envelope JSON-encoded as a POST body.
func breakerCall(method, u string, body []byte, key string) (model.BreakerStatus, int, error) {
	var st model.BreakerStatus
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return st, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return st, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return st, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if err := json.Unmarshal(respBody, &st); err != nil {
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
