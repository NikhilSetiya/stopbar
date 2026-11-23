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
	"os"
	"strings"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

const contactsUsage = `usage: stopbar contacts add <address> [--label L] --url URL --key KEY
       stopbar contacts approve <id> --url URL --key APPROVER_KEY
       stopbar contacts remove <address> --url URL --key KEY
       stopbar contacts list --url URL --key KEY`

// contactsCmd edits or lists the tenant's destination registry (CS-134) on a
// running stopbard over its authenticated API. The tenant and the acting
// identity come from the API key. An addition is pending until a different
// key approves it and active only after the server's cooling-off period; a
// removal applies at once.
func contactsCmd(args []string) error {
	return runContacts(args, os.Stdout)
}

func runContacts(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(contactsUsage)
	}
	op, rest := args[0], args[1:]
	var arg string
	switch op {
	case "add", "approve", "remove":
		// The argument comes before the flags (the flag package stops at the
		// first non-flag argument).
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return errors.New(contactsUsage)
		}
		arg, rest = rest[0], rest[1:]
	case "list":
	default:
		return errors.New(contactsUsage)
	}
	fs := flag.NewFlagSet("contacts "+op, flag.ContinueOnError)
	base := fs.String("url", "http://127.0.0.1:7777", "stopbard base URL")
	key := fs.String("key", "", "API key ('contacts' scope; 'approve' to approve)")
	label := fs.String("label", "", "add: a name for the address")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*label != "" && op != "add") {
		return errors.New(contactsUsage)
	}
	root := strings.TrimRight(*base, "/") + "/v1/contacts"
	var status int
	var body []byte
	var err error
	switch op {
	case "add":
		status, body, err = callAPI(http.MethodPost, root, *key, model.ContactRequest{Address: arg, Label: *label})
	case "approve":
		status, body, err = callAPI(http.MethodPost, root+"/"+url.PathEscape(arg)+"/approve", *key, nil)
	case "remove":
		status, body, err = callAPI(http.MethodDelete, root+"/"+url.PathEscape(arg), *key, nil)
	default:
		status, body, err = callAPI(http.MethodGet, root, *key, nil)
	}
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	var cs []model.Contact
	if op == "list" {
		var doc struct {
			Contacts []model.Contact `json:"contacts"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return fmt.Errorf("unexpected response: %w", err)
		}
		cs = doc.Contacts
	} else {
		var c model.Contact
		if err := json.Unmarshal(body, &c); err != nil {
			return fmt.Errorf("unexpected response: %w", err)
		}
		cs = []model.Contact{c}
	}
	for _, c := range cs {
		printContact(out, c)
	}
	switch op {
	case "add":
		_, _ = fmt.Fprintf(out, "requested %s (id %s): pending until another key approves it with `stopbar contacts approve %s`\n", cs[0].Address, cs[0].ID, cs[0].ID)
	case "approve":
		_, _ = fmt.Fprintf(out, "approved %s: known from %s\n", cs[0].Address, cs[0].ActiveFrom.Format(time.RFC3339))
	case "remove":
		_, _ = fmt.Fprintf(out, "removed %s (effective now)\n", cs[0].Address)
	default:
		_, _ = fmt.Fprintf(out, "%d entries\n", len(cs))
	}
	return nil
}

// printContact prints one entry, and every existing entry it looks like, so
// an approver sees an address-poisoning attempt before approving.
func printContact(out io.Writer, c model.Contact) {
	when := ""
	if c.ActiveFrom != nil {
		when = "active_from=" + c.ActiveFrom.Format(time.RFC3339)
	}
	_, _ = fmt.Fprintf(out, "%s\t%s\t%s\trequested_by=%s\t%s\t%s\n", c.ID, c.Address, c.Status, c.RequestedBy, when, c.Label)
	for _, s := range c.SimilarTo {
		_, _ = fmt.Fprintf(out, "  WARNING: looks like existing entry %s %q (possible address poisoning)\n", s.Address, s.Label)
	}
}

// callAPI sends one request to stopbard and returns the status and body.
func callAPI(method, u, key string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}
