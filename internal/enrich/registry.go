package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// Flags the destination registry adds to the intent (LLD §6.2). They need
// the tenant's registry, so the decoder can't set them.
const (
	FlagNewDestination     = "new_destination"     // not in the tenant's registry
	FlagSimilarDestination = "similar_destination" // looks like a registered address but isn't one (address poisoning)
)

// Similarity thresholds (LLD §6.2): address poisoning mints a vanity address
// that matches what wallets and explorers show of a known one, usually the
// first and last 4 hex digits (MetaMask: 0x1234…abcd) or a long run at one end
// (explorers show 8). A random address matches a given one this way with
// probability about 3 × 16⁻⁸, so false positives are negligible.
const (
	similarBothEnds = 4 // leading AND trailing hex digits in common
	similarOneEnd   = 8 // leading OR trailing hex digits in common
)

var (
	registryBucket = []byte("destinations_v1")
	reAddress      = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
)

// Contact is one registered destination.
type Contact struct {
	Address string    `json:"address"`
	Label   string    `json:"label,omitempty"`
	Source  string    `json:"source"` // who added it (e.g. "cli", "dev-world")
	AddedAt time.Time `json:"added_at"`
}

// Registry is the per-tenant destination registry (CS-133, FR-IR-2): the
// addresses a tenant has vetted. It lives in the shared state file, and every
// change is audited in the same transaction as the change.
//
// It is also an engine Enricher: it sets Destination.Known and
// SimilarToKnown and the matching flags. It reads the registry on every
// request, so a change is seen by the next evaluation.
type Registry struct {
	db  *store.DB
	log *audit.Log
}

// OpenRegistry uses the registry bucket in db. log records every change; a
// nil log makes the registry read-only (Add and Remove refuse).
func OpenRegistry(db *store.DB, log *audit.Log) (*Registry, error) {
	if db == nil {
		return nil, errors.New("registry: no state file")
	}
	if log != nil { // a read-only file can't create buckets; reads tolerate its absence
		if err := db.Bucket(registryBucket); err != nil {
			return nil, err
		}
	}
	return &Registry{db: db, log: log}, nil
}

// NormalizeAddress lowercases an EVM address and checks its shape.
func NormalizeAddress(a string) (string, error) {
	a = strings.ToLower(strings.TrimSpace(a))
	if !reAddress.MatchString(a) {
		return "", fmt.Errorf("registry: %q is not a 0x-prefixed 20-byte hex address", a)
	}
	return a, nil
}

// tenantPrefix quotes the tenant so no tenant name can reach into another's keys.
func tenantPrefix(tenant string) []byte { return []byte(strconv.Quote(tenant) + "/") }

func contactKey(tenant, addr string) []byte { return append(tenantPrefix(tenant), addr...) }

// Add registers addr for tenant. It reports false, and records nothing, if
// the address is already registered.
func (r *Registry) Add(tenant, addr, label, source string, now time.Time) (bool, error) {
	return r.change("add", tenant, addr, label, source, now)
}

// Remove unregisters addr for tenant. It reports false, and records nothing,
// if the address was not registered.
func (r *Registry) Remove(tenant, addr, source string, now time.Time) (bool, error) {
	return r.change("remove", tenant, addr, "", source, now)
}

func (r *Registry) change(op, tenant, addr, label, source string, now time.Time) (bool, error) {
	if r.log == nil {
		return false, errors.New("registry: opened read-only (no audit log)")
	}
	if tenant == "" {
		return false, errors.New("registry: tenant is required")
	}
	a, err := NormalizeAddress(addr)
	if err != nil {
		return false, err
	}
	changed := false
	err = r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(registryBucket)
		k := contactKey(tenant, a)
		exists := b.Get(k) != nil
		body := map[string]any{"op": op, "tenant": tenant, "address": a, "source": source}
		switch {
		case op == "add" && !exists:
			v, err := json.Marshal(Contact{Address: a, Label: label, Source: source, AddedAt: now.UTC()})
			if err != nil {
				return err
			}
			if err := b.Put(k, v); err != nil {
				return err
			}
			if label != "" {
				body["label"] = label
			}
		case op == "remove" && exists:
			if err := b.Delete(k); err != nil {
				return err
			}
		default:
			return nil // no change, nothing to audit
		}
		changed = true
		return r.log.AppendTx(tx, model.AuditEntry{Type: model.AuditDestination, Body: body})
	})
	if err != nil {
		return false, fmt.Errorf("registry: %s %s: %w", op, a, err)
	}
	return changed, nil
}

// List returns tenant's registered destinations, ordered by address.
func (r *Registry) List(tenant string) ([]Contact, error) {
	var out []Contact
	err := r.forEach(tenant, func(c Contact) { out = append(out, c) })
	return out, err
}

func (r *Registry) forEach(tenant string, fn func(Contact)) error {
	return r.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(registryBucket)
		if b == nil {
			return nil // nothing registered yet
		}
		p := tenantPrefix(tenant)
		c := b.Cursor()
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			var ct Contact
			if err := json.Unmarshal(v, &ct); err != nil {
				return fmt.Errorf("registry: corrupt entry %q: %w", k, err)
			}
			fn(ct)
		}
		return nil
	})
}

// Similar reports whether a and b (normalised addresses) are different but
// look alike the way address poisoning makes them look alike.
func Similar(a, b string) bool {
	if a == b || !reAddress.MatchString(a) || !reAddress.MatchString(b) {
		return false
	}
	x, y := a[2:], b[2:]
	pre, suf := 0, 0
	for pre < len(x) && x[pre] == y[pre] {
		pre++
	}
	for suf < len(x) && x[len(x)-1-suf] == y[len(y)-1-suf] {
		suf++
	}
	return (pre >= similarBothEnds && suf >= similarBothEnds) || pre >= similarOneEnd || suf >= similarOneEnd
}

// Enrich sets the destination facts from the tenant's registry. The sending
// wallet itself counts as known: moving funds to yourself (a swap's output,
// an unwrap) is not a new destination. An intent with no destination is
// neither known nor similar. A registry read failure is returned, so the
// engine fails closed.
func (r *Registry) Enrich(_ context.Context, er *model.EnrichedRequest) error {
	if er.Request.Action.Kind == model.KindToolCall || er.Intent.Destination == "" {
		return nil
	}
	dest := strings.ToLower(er.Intent.Destination)
	known := dest == strings.ToLower(er.Request.Action.From)
	similar := false
	if err := r.forEach(er.Request.Tenant, func(c Contact) {
		known = known || c.Address == dest
		similar = similar || Similar(c.Address, dest)
	}); err != nil {
		return err
	}
	er.Destination.Known = known
	er.Destination.SimilarToKnown = similar && !known
	if !known {
		addFlag(er, FlagNewDestination)
	}
	if er.Destination.SimilarToKnown {
		addFlag(er, FlagSimilarDestination)
	}
	return nil
}

// addFlag appends f to the intent's flags once. The slice is clipped first so
// the append never writes into a backing array the decoder's intent shares.
func addFlag(er *model.EnrichedRequest, f string) {
	if !slices.Contains(er.Intent.Flags, f) {
		er.Intent.Flags = append(slices.Clip(er.Intent.Flags), f)
	}
}
