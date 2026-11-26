package enrich

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/audit"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
	"github.com/NikhilSetiya/stopbar/internal/store"
)

// Flags the destination registry adds to the intent (LLD §6.2). They need
// the tenant's registry, so the decoder can't set them.
const (
	FlagNewDestination     = "new_destination"     // not active in the tenant's registry
	FlagSimilarDestination = "similar_destination" // looks like an active registered address but isn't one (address poisoning)
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

// DefaultCoolingOff is how long an approved addition waits before it counts
// as known (LLD §6.4): time for the rest of the team to see it and remove it.
const DefaultCoolingOff = 24 * time.Hour

var (
	// v2: entries carry the request/approval lifecycle (CS-134). CS-133's
	// destinations_v1 entries are never read: they become unknown, which only
	// tightens policy, and -dev-world re-seeds its own.
	registryBucket = []byte("destinations_v2")
	reAddress      = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
)

// Registry is the per-tenant destination registry (CS-133/134, FR-IR-2): the
// addresses a tenant has vetted. It lives in the shared state file, and every
// change is audited in the same transaction as the change.
//
// An addition is requested (pending), approved by a quorum of signed approver
// votes none of whose keys is bound to the requester, and counts as known only from active_from = approval +
// CoolingOff. A removal applies at once.
//
// It is also an engine Enricher: it sets Destination.Known and SimilarToKnown
// and the matching flags from the entries active at the server clock. It
// reads the registry on every request, so a change is seen by the next
// evaluation.
type Registry struct {
	db  *store.DB
	log *audit.Log
	// CoolingOff is the wait from approval to activation.
	CoolingOff time.Duration
	// Approvers and Quorum authorize additions (CS-151): Quorum distinct
	// approver owners must sign (spec/approval-signature-v1.md §3a). With no
	// Approvers, nothing can be approved.
	Approvers *approval.KeySet
	Quorum    int
	// Clock is for tests. stopbard never sets it: activation is judged
	// against the server clock.
	Clock func() time.Time
}

// OpenRegistry uses the registry bucket in db; log records every change.
func OpenRegistry(db *store.DB, log *audit.Log) (*Registry, error) {
	if db == nil || log == nil {
		return nil, errors.New("registry: needs a state file and an audit log")
	}
	if err := db.Bucket(registryBucket); err != nil {
		return nil, err
	}
	return &Registry{db: db, log: log, CoolingOff: DefaultCoolingOff}, nil
}

func (r *Registry) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// tenantPrefix quotes the tenant so no tenant name can reach into another's keys.
func tenantPrefix(tenant string) []byte { return []byte(strconv.Quote(tenant) + "/") }

func contactKey(tenant, addr string) []byte { return append(tenantPrefix(tenant), addr...) }

// Request records a pending addition of addr for tenant, requested by by. It
// checks addr against every one of the tenant's entries, active and pending,
// with the enricher's similarity rule and records each match (address and
// label), so the approver sees an address-poisoning attempt before
// approving. ErrContactExists if addr is already registered or pending.
func (r *Registry) Request(tenant, addr, label string, by auth.Identity, now time.Time) (model.Contact, error) {
	if tenant == "" || by.KeyID == "" {
		return model.Contact{}, errors.New("registry: a tenant and an authenticated requester key are required")
	}
	if err := (model.ContactRequest{Address: addr, Label: label}).Validate(); err != nil {
		return model.Contact{}, err
	}
	a, _ := model.NormalizeAddress(addr)
	id, err := newContactID()
	if err != nil {
		return model.Contact{}, err
	}
	c := model.Contact{ID: id, Tenant: tenant, Address: a, Label: label, Status: model.ContactPendingApproval,
		RequestedBy: by.KeyID, RequestedByAgent: by.AgentID, RequestedAt: now.UTC(), Quorum: r.Quorum, SimilarTo: []model.SimilarContact{}}
	err = r.db.Update(func(tx *bolt.Tx) error {
		c.SimilarTo = []model.SimilarContact{} // the store may run this more than once
		b := tx.Bucket(registryBucket)
		if b.Get(contactKey(tenant, a)) != nil {
			return model.ErrContactExists
		}
		if err := scan(b, tenant, func(o model.Contact) {
			if Similar(o.Address, a) {
				c.SimilarTo = append(c.SimilarTo, model.SimilarContact{Address: o.Address, Label: o.Label})
			}
		}); err != nil {
			return err
		}
		return r.put(tx, c, model.AuditContactRequest, map[string]any{"contact": c, "identity": by})
	})
	return c, err
}

// Approve verifies sig, a signed approval of tenant's pending addition id
// (spec/approval-signature-v1.md §3a, §8a), and records its vote. Once Quorum
// distinct owners hold a live vote the addition is approved and becomes
// active CoolingOff after now. A key bound to the requester is refused
// (ErrSelfApproval); any other failed check returns its *approval.VerifyError;
// a second live vote from the same owner returns ErrDuplicateVote. Each vote
// is audited in the same transaction as the change.
func (r *Registry) Approve(tenant, id string, sig approval.SignedContact, by auth.Identity, now time.Time) (model.Contact, error) {
	if r.Approvers == nil {
		return model.Contact{}, errors.New("registry: no approver keys configured; contact approval is disabled")
	}
	var c model.Contact
	err := r.db.Update(func(tx *bolt.Tx) error {
		found := false
		if err := scan(tx.Bucket(registryBucket), tenant, func(o model.Contact) {
			if o.ID == id {
				c, found = o, true
			}
		}); err != nil {
			return err
		}
		switch {
		case !found:
			return model.ErrNoContact
		case c.ApprovedAt != nil:
			return model.ErrContactApproved
		}
		k, err := approval.VerifyContact(r.Approvers, sig, approval.ContactWant{Tenant: tenant, ContactID: c.ID, Address: c.Address,
			RequesterKeyID: c.RequestedBy, RequesterAgentID: c.RequestedByAgent}, now)
		var ve *approval.VerifyError
		if errors.As(err, &ve) && ve.Code == approval.CodeSelfApproval {
			return model.ErrSelfApproval
		} else if err != nil {
			return err
		}
		tally := approval.NewTally(r.Quorum, c.RequestedBy, c.RequestedByAgent)
		live := []model.BreakerVote{}
		for _, v := range c.Votes {
			if now.Before(v.ExpiresAt) {
				live = append(live, v)
				_, _ = tally.Add(approval.Vote{Kid: v.Approver, Owner: approval.Owner{AgentID: v.OwnerAgentID, KeyID: v.OwnerKeyID},
					Decision: approval.Approve, Expiry: v.ExpiresAt}, now)
			}
		}
		res, err := tally.Add(approval.VoteFromContact(k, sig), now)
		if errors.Is(err, approval.ErrDuplicateVote) {
			return model.ErrDuplicateVote
		} else if err != nil {
			return err
		}
		c.Votes = append(live, model.BreakerVote{Approver: k.ID, OwnerAgentID: k.Owner.AgentID, OwnerKeyID: k.Owner.KeyID,
			At: now.UTC(), ExpiresAt: time.Unix(sig.Expiry, 0).UTC()})
		c.Quorum = r.Quorum
		body := map[string]any{"event": "vote", "contact": c, "identity": by, "approver": k.ID, "kid": k.Kid, "owner": k.Owner}
		if res.Outcome == approval.Approved {
			ids := make([]string, len(c.Votes))
			for i, v := range c.Votes {
				ids[i] = v.Approver
			}
			at := now.UTC()
			from := at.Add(r.CoolingOff)
			c.ApprovedBy, c.ApprovedAt, c.ActiveFrom, c.Votes = strings.Join(ids, ","), &at, &from, nil
			body["event"], body["contact"], body["cooling_off"] = "approved", c, r.CoolingOff.String()
		}
		c.Status = c.StatusAt(now)
		return r.put(tx, c, model.AuditContactApproval, body)
	})
	return c, err
}

// Remove deletes tenant's entry for addr, whatever its status, at once.
func (r *Registry) Remove(tenant, addr string, by auth.Identity, now time.Time) (model.Contact, error) {
	a, err := model.NormalizeAddress(addr)
	if err != nil {
		return model.Contact{}, err
	}
	var c model.Contact
	err = r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(registryBucket)
		k := contactKey(tenant, a)
		v := b.Get(k)
		if v == nil {
			return model.ErrNoContact
		}
		if err := json.Unmarshal(v, &c); err != nil {
			return fmt.Errorf("registry: corrupt entry %q: %w", k, err)
		}
		c.Status = c.StatusAt(now)
		if err := b.Delete(k); err != nil {
			return err
		}
		return r.log.AppendTx(tx, model.AuditEntry{Type: model.AuditContactRemoval,
			Body: map[string]any{"contact": c, "identity": by}})
	})
	return c, err
}

// Seed adds addr for tenant as already active, unless it is registered. It is
// for -dev-world only: the operator's world file is the approval. It reports
// whether it added anything.
func (r *Registry) Seed(tenant, addr string, now time.Time) (bool, error) {
	a, err := model.NormalizeAddress(addr)
	if err != nil {
		return false, err
	}
	id, err := newContactID()
	if err != nil {
		return false, err
	}
	at := now.UTC()
	c := model.Contact{ID: id, Tenant: tenant, Address: a, Status: model.ContactActive, RequestedBy: "dev-world",
		RequestedAt: at, ApprovedBy: "dev-world", ApprovedAt: &at, ActiveFrom: &at, SimilarTo: []model.SimilarContact{}}
	added := false
	err = r.db.Update(func(tx *bolt.Tx) error {
		added = false // the store may run this more than once
		if tx.Bucket(registryBucket).Get(contactKey(tenant, a)) != nil {
			return nil
		}
		added = true
		return r.put(tx, c, model.AuditContactRequest, map[string]any{"contact": c, "identity": "dev-world"})
	})
	return added, err
}

// put stores c and appends its audit record in the same transaction.
func (r *Registry) put(tx *bolt.Tx, c model.Contact, t model.AuditRecordType, body any) error {
	v, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := tx.Bucket(registryBucket).Put(contactKey(c.Tenant, c.Address), v); err != nil {
		return err
	}
	return r.log.AppendTx(tx, model.AuditEntry{Type: t, Body: body})
}

func newContactID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "ct_" + hex.EncodeToString(b[:]), nil
}

// List returns tenant's entries ordered by address, with status as of now.
func (r *Registry) List(tenant string, now time.Time) ([]model.Contact, error) {
	out := []model.Contact{}
	err := r.db.View(func(tx *bolt.Tx) error {
		return scan(tx.Bucket(registryBucket), tenant, func(c model.Contact) {
			c.Status = c.StatusAt(now)
			out = append(out, c)
		})
	})
	return out, err
}

func scan(b *bolt.Bucket, tenant string, fn func(model.Contact)) error {
	p := tenantPrefix(tenant)
	c := b.Cursor()
	for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
		var ct model.Contact
		if err := json.Unmarshal(v, &ct); err != nil {
			return fmt.Errorf("registry: corrupt entry %q: %w", k, err)
		}
		fn(ct)
	}
	return nil
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

// Enrich sets the destination facts from the tenant's registry entries that
// are active at the server clock: a pending or cooling-off addition is still
// a new destination. The sending wallet itself counts as known: moving funds
// to yourself (a swap's output, an unwrap) is not a new destination. An
// intent with no destination is neither known nor similar. A registry read
// failure is returned, so the engine fails closed.
func (r *Registry) Enrich(_ context.Context, er *model.EnrichedRequest) error {
	if er.Request.Action.Kind == model.KindToolCall || er.Intent.Destination == "" {
		return nil
	}
	now := r.now()
	dest := strings.ToLower(er.Intent.Destination)
	known := dest == strings.ToLower(er.Request.Action.From)
	similar := false
	if err := r.db.View(func(tx *bolt.Tx) error {
		return scan(tx.Bucket(registryBucket), er.Request.Tenant, func(c model.Contact) {
			if c.StatusAt(now) != model.ContactActive {
				return
			}
			known = known || c.Address == dest
			similar = similar || Similar(c.Address, dest)
		})
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
