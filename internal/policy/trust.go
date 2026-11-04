package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
)

// TrustFile is the name of a bundle's tool trust map. It is hashed with the
// policies (it is policy), so changing one label changes the bundle hash.
const TrustFile = "tool-trust.json"

// UntrustedToolOutput is the taint label a session gains once it has
// evaluated a call to a tool whose output carries third-party content.
const UntrustedToolOutput = "untrusted_tool_output"

// ToolTrust classifies every tool a tool-call bundle knows. It is decided
// from tool definitions alone and frozen with the bundle (research
// pre-registration §3).
type ToolTrust struct {
	// Exactly one of these per tool.
	ReadOnlyTools      []string `json:"read_only_tools"`
	StateChangingTools []string `json:"state_changing_tools"`
	// UntrustedOutputTools return content not authored by the user in this
	// session; calling one taints the session.
	UntrustedOutputTools []string `json:"untrusted_output_tools"`
	// AccountIdentityTools change credentials or the account holder's
	// identity (a subset of StateChangingTools).
	AccountIdentityTools []string `json:"account_identity_tools"`
	// Rationale per tool, from its definition; documentation, but hashed.
	Rationale map[string]string `json:"rationale"`
}

func parseTrust(b []byte) (*ToolTrust, error) {
	var t ToolTrust
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%s: %w", TrustFile, err)
	}
	var problems []string
	known := map[string]bool{}
	for _, tool := range append(slices.Clone(t.ReadOnlyTools), t.StateChangingTools...) {
		if known[tool] {
			problems = append(problems, fmt.Sprintf("tool %q is listed twice across read_only_tools and state_changing_tools", tool))
		}
		known[tool] = true
	}
	for _, tool := range t.UntrustedOutputTools {
		if !known[tool] {
			problems = append(problems, fmt.Sprintf("untrusted_output_tools: %q is not a declared tool", tool))
		}
	}
	for _, tool := range t.AccountIdentityTools {
		if !slices.Contains(t.StateChangingTools, tool) {
			problems = append(problems, fmt.Sprintf("account_identity_tools: %q must be a state-changing tool", tool))
		}
	}
	for tool := range known {
		if t.Rationale[tool] == "" {
			problems = append(problems, fmt.Sprintf("tool %q has no rationale", tool))
		}
	}
	if len(known) == 0 {
		problems = append(problems, "no tools declared")
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, errors.New(TrustFile + ": " + fmt.Sprint(problems))
	}
	return &t, nil
}

func (t *ToolTrust) known(tool string) bool {
	return slices.Contains(t.ReadOnlyTools, tool) || slices.Contains(t.StateChangingTools, tool)
}
