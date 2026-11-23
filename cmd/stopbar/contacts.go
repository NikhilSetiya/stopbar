package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/enrich"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

const contactsUsage = "usage: stopbar contacts add|remove <address> --state-dir DIR --tenant T [--label L] [--decision-key FILE]\n       stopbar contacts list --state-dir DIR --tenant T"

// contactsCmd edits or lists a tenant's destination registry (CS-133) in the
// state file. It works on the file directly, never over the API: vetting a
// destination loosens policy, so it takes access to the operator's state
// directory, not a requester credential. stopbard holds the file's lock, so
// stop it first.
func contactsCmd(args []string) error {
	return runContacts(args, os.Stdout, time.Now)
}

func runContacts(args []string, out io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		return errors.New(contactsUsage)
	}
	op, rest := args[0], args[1:]
	var addr string
	if op == "add" || op == "remove" {
		// The address comes before the flags (the flag package stops at the
		// first non-flag argument).
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return errors.New(contactsUsage)
		}
		addr, rest = rest[0], rest[1:]
	} else if op != "list" {
		return errors.New(contactsUsage)
	}
	fs := flag.NewFlagSet("contacts "+op, flag.ContinueOnError)
	stateDir := fs.String("state-dir", "", "stopbard state directory (holds state.db)")
	tenant := fs.String("tenant", "", "tenant whose registry to use (stopbard's -tenant)")
	label := fs.String("label", "", "add: a name for the address")
	keyFile := fs.String("decision-key", "", "add/remove: sign an audit checkpoint over the change with this decision key")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() != 0 || *stateDir == "" || *tenant == "" {
		return errors.New(contactsUsage)
	}
	path := filepath.Join(*stateDir, "state.db")

	if op == "list" {
		db, err := store.OpenReadOnly(path)
		if err != nil {
			return lockHint(err)
		}
		defer func() { _ = db.Close() }()
		reg, err := enrich.OpenRegistry(db, nil)
		if err != nil {
			return err
		}
		cs, err := reg.List(*tenant)
		if err != nil {
			return err
		}
		for _, c := range cs {
			_, _ = fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", c.Address, c.AddedAt.Format(time.RFC3339), c.Source, c.Label)
		}
		_, _ = fmt.Fprintf(out, "%d known destinations for tenant %q\n", len(cs), *tenant)
		return nil
	}

	var ring *decision.KeyRing
	if *keyFile != "" {
		k, err := decision.LoadKeyFile(*keyFile)
		if err != nil {
			return err
		}
		ring = decision.NewKeyRing(k)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no state file at %s: %w", path, err)
	}
	db, err := store.Open(path)
	if err != nil {
		return lockHint(err)
	}
	defer func() { _ = db.Close() }()
	cfg := audit.Config{DB: db}
	if ring != nil {
		cfg.Signer = ring
	}
	lg, err := audit.New(cfg)
	if err != nil {
		return err
	}
	reg, err := enrich.OpenRegistry(db, lg)
	if err != nil {
		return err
	}
	var changed bool
	if op == "add" {
		changed, err = reg.Add(*tenant, addr, *label, "cli", now())
	} else {
		changed, err = reg.Remove(*tenant, addr, "cli", now())
	}
	if err != nil {
		return err
	}
	a, _ := enrich.NormalizeAddress(addr)
	if !changed {
		_, _ = fmt.Fprintf(out, "%s: no change (%s for tenant %q)\n", a, map[string]string{"add": "already registered", "remove": "not registered"}[op], *tenant)
		return nil
	}
	_, _ = fmt.Fprintf(out, "%s: %s for tenant %q (audited)\n", a, map[string]string{"add": "added", "remove": "removed"}[op], *tenant)
	if ring != nil {
		if err := lg.Checkpoint(); err != nil {
			return fmt.Errorf("change recorded, but the audit checkpoint failed: %w", err)
		}
		_, _ = fmt.Fprintln(out, "audit checkpoint signed")
	}
	return nil
}

// lockHint explains the usual cause of a failure to open the state file.
func lockHint(err error) error {
	return fmt.Errorf("%w (is stopbard running? it holds the state file; stop it first)", err)
}
