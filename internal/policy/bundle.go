// Package policy loads a Cedar policy bundle and evaluates enriched requests
// against it (CS-111/112, LLD §5, ADR 0001).
//
// Outcomes combine as deny > escalate > allow with default deny. Forbid
// policies annotated @outcome("escalate") form their own set; every other
// policy goes in the main set. Any Cedar evaluation error fails closed:
// cedar-go skips erroring policies, which would otherwise fail open.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"

	"github.com/NikhilSetiya/stopbar/internal/canon"
)

// Bundle is a loaded, validated policy bundle. It is immutable after Load.
type Bundle struct {
	main      *cedar.PolicySet
	escalate  *cedar.PolicySet
	validator *validate.Validator
	messages  map[cedar.PolicyID]string
	trust     *ToolTrust // tool-call bundles only
	hash      string
}

// Trust is the bundle's tool trust map, or nil for bundles without one.
func (b *Bundle) Trust() *ToolTrust { return b.trust }

// Hash is the bundle hash bound into every decision (LLD §5.4).
func (b *Bundle) Hash() string { return b.hash }

// Load reads every *.cedar file and exactly one *.cedarschema from dir
// (non-recursive), validates each policy against the schema, and builds the
// two policy sets. Every problem is reported with file:line.
func Load(dir string) (*Bundle, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var policyFiles, schemaFiles []string
	files := map[string][]byte{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".cedar") && !strings.HasSuffix(name, ".cedarschema") && name != TrustFile) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files[name] = b
		if name == TrustFile {
			continue
		}
		if strings.HasSuffix(name, ".cedarschema") {
			schemaFiles = append(schemaFiles, name)
		} else {
			policyFiles = append(policyFiles, name)
		}
	}
	sort.Strings(policyFiles)
	if len(schemaFiles) != 1 {
		return nil, fmt.Errorf("policy: %s must contain exactly one .cedarschema file, found %d", dir, len(schemaFiles))
	}
	if len(policyFiles) == 0 {
		return nil, fmt.Errorf("policy: %s contains no .cedar files", dir)
	}

	var s schema.Schema
	s.SetFilename(schemaFiles[0])
	if err := s.UnmarshalCedar(files[schemaFiles[0]]); err != nil {
		return nil, fmt.Errorf("policy: schema: %w", err)
	}
	resolved, err := s.Resolve()
	if err != nil {
		return nil, fmt.Errorf("policy: schema: %w", err)
	}
	b := &Bundle{
		main: cedar.NewPolicySet(), escalate: cedar.NewPolicySet(),
		validator: validate.New(resolved), messages: map[cedar.PolicyID]string{},
	}
	if raw, ok := files[TrustFile]; ok {
		if b.trust, err = parseTrust(raw); err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
	}

	var problems []string
	seen := map[cedar.PolicyID]string{}
	for _, name := range policyFiles {
		ps, err := cedar.NewPolicySetFromBytes(name, files[name])
		if err != nil {
			// cedar-go reports parse positions as <input>:line:col.
			problems = append(problems, name+": "+strings.Replace(err.Error(), "<input>", name, 1))
			continue
		}
		for _, p := range ps.All() {
			if msg := b.add(p, seen); msg != "" {
				pos := p.Position()
				problems = append(problems, fmt.Sprintf("%s:%d: %s", pos.Filename, pos.Line, msg))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, errors.New("policy: invalid bundle:\n  " + strings.Join(problems, "\n  "))
	}
	b.hash, err = bundleHash(files)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// add files one policy into the right set, returning a problem or "".
func (b *Bundle) add(p *cedar.Policy, seen map[cedar.PolicyID]string) string {
	ann := p.Annotations()
	idv, ok := ann["id"]
	if !ok || idv == "" {
		return `policy has no @id("…") annotation`
	}
	id := cedar.PolicyID(idv)
	if prev, dup := seen[id]; dup {
		return fmt.Sprintf("duplicate @id %q (first defined at %s)", id, prev)
	}
	pos := p.Position()
	seen[id] = fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
	for k := range ann {
		switch k {
		case "id", "outcome", "message":
		default:
			return fmt.Sprintf("policy %s: unknown annotation @%s", id, k)
		}
	}
	if err := b.validator.Policy(string(id), (*xast.Policy)(p.AST())); err != nil {
		return fmt.Sprintf("policy %s fails schema validation: %v", id, err)
	}
	if m, ok := ann["message"]; ok {
		b.messages[id] = string(m)
	}
	out, has := ann["outcome"]
	switch {
	case p.Effect() == cedar.Permit && has:
		return fmt.Sprintf("policy %s: @outcome is only valid on forbid policies", id)
	case p.Effect() == cedar.Permit:
		b.main.Add(id, p)
	case !has || out == "deny":
		b.main.Add(id, p) // an unannotated forbid denies
	case out == "escalate":
		b.escalate.Add(id, p)
	default:
		return fmt.Sprintf("policy %s: @outcome must be \"deny\" or \"escalate\", got %q", id, out)
	}
	return ""
}

// bundleHash = sha256(JCS({"v":1,"files":[{"name","sha256"}…] sorted by name}))
// over every .cedar, the .cedarschema and tool-trust.json.
// over the exact source bytes (ADR 0001 condition 3). It is independent of
// file order and of how cedar-go would re-serialise the policies.
func bundleHash(files map[string][]byte) (string, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	list := make([]map[string]string, len(names))
	for i, n := range names {
		sum := sha256.Sum256(files[n])
		list[i] = map[string]string{"name": n, "sha256": hex.EncodeToString(sum[:])}
	}
	return canon.HashJSON(map[string]any{"v": 1, "files": list})
}
