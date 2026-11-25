package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Destination registry wire types (CS-134, LLD §4.1 and §6.4). Adding a
// contact loosens policy, so an addition is pending until an approver other
// than the requester approves it, and active only after a cooling-off period
// from that approval. Removing one tightens policy and applies at once.

// ContactStatus is where a contact is in its lifecycle, as of the server
// clock when it is read.
type ContactStatus string

const (
	ContactPendingApproval ContactStatus = "pending_approval" // requested, not yet approved
	ContactCoolingOff      ContactStatus = "cooling_off"      // approved, active_from not reached
	ContactActive          ContactStatus = "active"           // counts as a known destination
)

// MaxContactLabel bounds a contact label (bytes).
const MaxContactLabel = 128

// Contact errors, mapped to gateway codes.
var (
	ErrContactExists   = errors.New("contact: address already registered or pending for this tenant")
	ErrNoContact       = errors.New("contact: no such contact for this tenant")
	ErrContactApproved = errors.New("contact: already approved")
	ErrSelfApproval    = errors.New("contact: the requester may not approve their own addition")
)

var reLowerAddr = regexp.MustCompile(`^0x[0-9a-f]{40}$`)

// NormalizeAddress lowercases an EVM address and checks its shape.
func NormalizeAddress(a string) (string, error) {
	a = strings.ToLower(strings.TrimSpace(a))
	if !reLowerAddr.MatchString(a) {
		return "", fmt.Errorf("%q is not a 0x-prefixed 20-byte hex address", a)
	}
	return a, nil
}

// ContactRequest is the body of POST /v1/contacts: a requested addition to
// the authenticated tenant's registry. The tenant and requester come from
// the credential, never the body.
type ContactRequest struct {
	Address string `json:"address"`
	Label   string `json:"label,omitempty"`
}

// Validate reports every problem at once.
func (r ContactRequest) Validate() error {
	var p []string
	if !reHexAddr.MatchString(r.Address) {
		p = append(p, "address must be a 0x-prefixed 20-byte address")
	}
	if len(r.Label) > MaxContactLabel || !utf8.ValidString(r.Label) {
		p = append(p, fmt.Sprintf("label must be valid UTF-8 of at most %d bytes", MaxContactLabel))
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// Contact is one registry entry, as stored and as served.
type Contact struct {
	ID          string        `json:"id"`
	Tenant      string        `json:"tenant"`
	Address     string        `json:"address"` // lowercase
	Label       string        `json:"label,omitempty"`
	Status      ContactStatus `json:"status"` // derived from the fields below at read time
	RequestedBy string        `json:"requested_by"`
	// RequestedByAgent is the requester's agent id, so an approver key bound
	// to that agent cannot approve it (spec/approval-signature-v1.md §7).
	RequestedByAgent string    `json:"requested_by_agent,omitempty"`
	RequestedAt      time.Time `json:"requested_at"`
	// Votes are the live signed approvals toward the quorum (CS-151), until
	// it is met; ApprovedBy is then the approver ids that met it.
	Votes      []BreakerVote `json:"votes,omitempty"`
	Quorum     int           `json:"quorum,omitempty"`
	ApprovedBy string        `json:"approved_by,omitempty"`
	ApprovedAt *time.Time    `json:"approved_at,omitempty"`
	ActiveFrom *time.Time    `json:"active_from,omitempty"`
	// SimilarTo lists every one of the tenant's entries (active or pending)
	// this address looks like (address poisoning), computed when it was
	// requested, so the approver sees it before approving.
	SimilarTo []SimilarContact `json:"similar_to"`
}

// SimilarContact is an existing registry entry a requested addition looks like.
type SimilarContact struct {
	Address string `json:"address"`
	Label   string `json:"label,omitempty"`
}

// StatusAt derives the status at now. An entry with no approval is pending;
// an approved one is cooling off until active_from.
func (c Contact) StatusAt(now time.Time) ContactStatus {
	switch {
	case c.ApprovedAt == nil || c.ActiveFrom == nil:
		return ContactPendingApproval
	case now.Before(*c.ActiveFrom):
		return ContactCoolingOff
	default:
		return ContactActive
	}
}

// Validate reports every problem at once.
func (c Contact) Validate() error {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	if c.ID == "" {
		add("id is required")
	}
	if c.Tenant == "" {
		add("tenant is required")
	}
	if !reLowerAddr.MatchString(c.Address) {
		add("address must be a lowercase 0x-prefixed 20-byte address")
	}
	if len(c.Label) > MaxContactLabel || !utf8.ValidString(c.Label) {
		add("label must be valid UTF-8 of at most %d bytes", MaxContactLabel)
	}
	switch c.Status {
	case ContactPendingApproval, ContactCoolingOff, ContactActive:
	default:
		add("status must be pending_approval, cooling_off or active")
	}
	if c.RequestedBy == "" {
		add("requested_by is required")
	}
	if c.RequestedAt.IsZero() {
		add("requested_at is required")
	}
	if (c.ApprovedAt == nil) != (c.ActiveFrom == nil) || (c.ApprovedAt == nil) != (c.ApprovedBy == "") {
		add("approved_by, approved_at and active_from are set together")
	}
	if c.ApprovedAt != nil && c.ActiveFrom != nil && c.ActiveFrom.Before(*c.ApprovedAt) {
		add("active_from must not be before approved_at")
	}
	if c.ApprovedAt == nil && c.Status != ContactPendingApproval {
		add("an unapproved contact must be pending_approval")
	}
	if c.SimilarTo == nil {
		add("similar_to is required (use [] for none)")
	}
	for _, s := range c.SimilarTo {
		if !reLowerAddr.MatchString(s.Address) || s.Address == c.Address {
			add("similar_to entries must be other lowercase 0x-prefixed 20-byte addresses")
			break
		}
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}
