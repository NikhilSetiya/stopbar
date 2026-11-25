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

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

const contactsUsage = `usage: stopbar contacts add <address> [--label L] --url URL --key KEY
       stopbar contacts approve <id> --approver-key FILE --url URL --key KEY
       stopbar contacts remove <address> --url URL --key KEY
       stopbar contacts list --url URL --key KEY`

// contactsCmd edits or lists the tenant's destination registry (CS-134) on a
// running stopbard over its authenticated API. The tenant and the acting
// identity come from the API key. An addition is pending until a quorum of
// approver keys not bound to the requester sign it (CS-151; the approver key
// signs locally and never leaves this process) and active only after the server's cooling-off period; a
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
	key := fs.String("key", "", "API key ('contacts' scope; to approve, any key that can list contacts: it never authorizes the approval)")
	label := fs.String("label", "", "add: a name for the address")
	approverKey := fs.String("approver-key", "", "approve: local approver private key file (signs the approval)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*label != "" && op != "add") || ((*approverKey != "") != (op == "approve")) {
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
		var sig approval.SignedContact
		if sig, err = signContact(root, arg, *key, *approverKey); err != nil {
			return err
		}
		status, body, err = callAPI(http.MethodPost, root+"/"+url.PathEscape(arg)+"/approve", *key, sig)
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
		if cs[0].ActiveFrom == nil {
			_, _ = fmt.Fprintf(out, "vote recorded on %s: %d of %d approvers; another distinct approver must sign\n", cs[0].Address, len(cs[0].Votes), cs[0].Quorum)
		} else {
			_, _ = fmt.Fprintf(out, "approved %s: known from %s\n", cs[0].Address, cs[0].ActiveFrom.Format(time.RFC3339))
		}
	case "remove":
		_, _ = fmt.Fprintf(out, "removed %s (effective now)\n", cs[0].Address)
	default:
		_, _ = fmt.Fprintf(out, "%d entries\n", len(cs))
	}
	return nil
}

// signContact looks pending addition id up in the tenant's listing and signs
// an approval of exactly that entry with the approver key in keyFile
// (spec/approval-signature-v1.md §3a).
func signContact(root, id, key, keyFile string) (approval.SignedContact, error) {
	priv, err := approval.LoadKeyFile(keyFile)
	if err != nil {
		return approval.SignedContact{}, err
	}
	status, body, err := callAPI(http.MethodGet, root, key, nil)
	if err != nil {
		return approval.SignedContact{}, err
	}
	if status != http.StatusOK {
		return approval.SignedContact{}, fmt.Errorf("could not fetch the addition to sign (HTTP %d): %s", status, strings.TrimSpace(string(body)))
	}
	var doc struct {
		Contacts []model.Contact `json:"contacts"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return approval.SignedContact{}, fmt.Errorf("unexpected response: %w", err)
	}
	for _, c := range doc.Contacts {
		if c.ID == id {
			return approval.SignContact(priv, approval.ContactObject{Tenant: c.Tenant, ContactID: c.ID, Address: c.Address,
				Decision: approval.Approve, Expiry: time.Now().Add(50 * time.Minute).Unix()}) // under the 1h bound, clock skew included
		}
	}
	return approval.SignedContact{}, fmt.Errorf("HTTP 404: no contact %q for this tenant", id)
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
