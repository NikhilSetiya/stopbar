package model

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// TypedData is an EIP-712 payload exactly as eth_signTypedData_v4 takes it
// (CS-514). Validation is strict and structural: every value must have the
// one JSON shape its declared type allows, so the stdlib decoder and the
// signer's EIP-712 hasher (go-ethereum, internal/signer) cannot read the same
// payload two ways.
type TypedData struct {
	Types       map[string][]TypedField `json:"types"`
	PrimaryType string                  `json:"primaryType"`
	Domain      map[string]any          `json:"domain"`
	Message     map[string]any          `json:"message"`
}

// TypedField is one member of an EIP-712 struct type.
type TypedField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// DomainType is the EIP-712 domain separator's type name.
const DomainType = "EIP712Domain"

// domainFields are the EIP-712 domain members, in the order the standard
// lists them. A domain must declare the members it uses in this order.
var domainFields = []TypedField{
	{"name", "string"}, {"version", "string"}, {"chainId", "uint256"},
	{"verifyingContract", "address"}, {"salt", "bytes32"},
}

// maxTypedDepth bounds how deeply typed-data values may nest.
const maxTypedDepth = 16

const maxSafeInt = 1 << 53

var (
	reIdent   = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	reArray   = regexp.MustCompile(`^(.+)\[([1-9][0-9]{0,3})?\]$`)
	reSized   = regexp.MustCompile(`^(u?int|bytes)([1-9][0-9]*)$`)
	reInt     = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	reMessage = regexp.MustCompile(`^0x([0-9a-fA-F]{2})+$`)
)

// atomic reports whether t is an EIP-712 atomic type: bool, address, string,
// bytes, bytes1..bytes32, uint8..uint256 or int8..int256 (steps of 8). A bare
// uint or int is not allowed.
func atomic(t string) bool {
	switch t {
	case "bool", "address", "string", "bytes":
		return true
	}
	m := reSized.FindStringSubmatch(t)
	if m == nil {
		return false
	}
	n, _ := strconv.Atoi(m[2])
	if m[1] == "bytes" {
		return n <= 32
	}
	return n%8 == 0 && n <= 256
}

// IntBits returns the signedness and width of an EIP-712 integer type.
func IntBits(t string) (signed bool, bits int, ok bool) {
	m := reSized.FindStringSubmatch(t)
	if m == nil || m[1] == "bytes" || !atomic(t) {
		return false, 0, false
	}
	n, _ := strconv.Atoi(m[2])
	return m[1] == "int", n, true
}

// TypedInt reads an EIP-712 integer value: a decimal string, or a JSON number
// that is an integer of magnitude at most 2^53. Hex strings are refused, so
// only one spelling of each value exists.
func TypedInt(v any) (*big.Int, error) {
	switch x := v.(type) {
	case string:
		if !reInt.MatchString(x) || x == "-0" {
			return nil, fmt.Errorf("%q is not a decimal integer string", x)
		}
		n, _ := new(big.Int).SetString(x, 10)
		return n, nil
	case float64:
		if x != math.Trunc(x) || math.Abs(x) > maxSafeInt {
			return nil, fmt.Errorf("number %v is not an integer within ±2^53 (send it as a decimal string)", x)
		}
		return big.NewInt(int64(x)), nil
	default:
		return nil, fmt.Errorf("integer must be a decimal string or a JSON number, not %T", v)
	}
}

// Problems lists every structural problem with td for a request on chain.
func (td *TypedData) Problems(chain uint64) []string {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf("action.typed_data."+f, a...)) }
	if len(td.Types) == 0 {
		return []string{"action.typed_data.types is required"}
	}
	names := make([]string, 0, len(td.Types))
	for n := range td.Types {
		names = append(names, n)
	}
	slices.Sort(names) // deterministic problem order
	for _, n := range names {
		fields := td.Types[n]
		if !reIdent.MatchString(n) || atomic(n) {
			add("types: %q is not a valid struct type name", n)
		}
		if len(fields) == 0 {
			add("types.%s has no fields", n)
		}
		seen := map[string]bool{}
		for i, f := range fields {
			if !reIdent.MatchString(f.Name) || seen[f.Name] {
				add("types.%s[%d]: field name %q is invalid or repeated", n, i, f.Name)
			}
			seen[f.Name] = true
			base := f.Type
			for {
				m := reArray.FindStringSubmatch(base)
				if m == nil {
					break
				}
				base = m[1]
			}
			if !atomic(base) && (base == DomainType || td.Types[base] == nil) {
				add("types.%s.%s: type %q is not atomic or a declared struct", n, f.Name, f.Type)
			}
		}
	}

	dom, ok := td.Types[DomainType]
	if !ok {
		add("types.%s is required", DomainType)
	}
	if len(p) > 0 {
		return p // values can't be checked against broken types
	}
	{
		i := 0
		for _, f := range dom {
			for i < len(domainFields) && domainFields[i].Name != f.Name {
				i++
			}
			if i == len(domainFields) || domainFields[i] != f {
				add("types.%s: %s %s is not a standard domain member in standard order (name, version, chainId, verifyingContract, salt)", DomainType, f.Name, f.Type)
				break
			}
			i++
		}
		if !slices.ContainsFunc(dom, func(f TypedField) bool { return f.Name == "chainId" }) {
			add("domain.chainId is required: a signature without one is valid on every chain")
		} else if c, err := TypedInt(td.Domain["chainId"]); err == nil && (!c.IsUint64() || c.Uint64() != chain) {
			add("domain.chainId %s does not match action.chain_id %d", c, chain)
		}
		for _, f := range dom {
			if s, ok := td.Domain[f.Name].(string); ok && s == "" {
				add("domain.%s must not be empty", f.Name) // go-ethereum drops empty domain members
			}
		}
	}

	switch {
	case td.PrimaryType == "" || td.PrimaryType == DomainType || td.Types[td.PrimaryType] == nil:
		add("primaryType %q must name a declared struct type other than %s", td.PrimaryType, DomainType)
	case td.Message == nil:
		add("message is required")
	default:
		p = append(p, td.check(td.PrimaryType, td.Message, "action.typed_data.message", 0)...)
	}
	if td.Domain == nil {
		add("domain is required")
	} else {
		p = append(p, td.check(DomainType, td.Domain, "action.typed_data.domain", 0)...)
	}
	return p
}

// check validates value v against type t at path.
func (td *TypedData) check(t string, v any, path string, depth int) []string {
	bad := func(f string, a ...any) []string { return []string{path + ": " + fmt.Sprintf(f, a...)} }
	if depth > maxTypedDepth {
		return bad("nested deeper than %d", maxTypedDepth)
	}
	if m := reArray.FindStringSubmatch(t); m != nil {
		arr, ok := v.([]any)
		if !ok {
			return bad("%s must be a JSON array", t)
		}
		if m[2] != "" {
			if n, _ := strconv.Atoi(m[2]); len(arr) != n {
				return bad("%s must have exactly %d elements, has %d", t, n, len(arr))
			}
		}
		var p []string
		for i, el := range arr {
			p = append(p, td.check(m[1], el, fmt.Sprintf("%s[%d]", path, i), depth+1)...)
		}
		return p
	}
	if fields, ok := td.Types[t]; ok {
		obj, ok := v.(map[string]any)
		if !ok {
			return bad("%s must be a JSON object", t)
		}
		var p []string
		for k := range obj {
			if !slices.ContainsFunc(fields, func(f TypedField) bool { return f.Name == k }) {
				p = append(p, fmt.Sprintf("%s: %q is not a member of %s", path, k, t))
			}
		}
		slices.Sort(p)
		for _, f := range fields {
			fv, ok := obj[f.Name]
			if !ok {
				p = append(p, fmt.Sprintf("%s.%s is missing", path, f.Name))
				continue
			}
			p = append(p, td.check(f.Type, fv, path+"."+f.Name, depth+1)...)
		}
		return p
	}
	switch t {
	case "bool":
		if _, ok := v.(bool); !ok {
			return bad("bool must be true or false")
		}
	case "string":
		if _, ok := v.(string); !ok {
			return bad("string must be a JSON string")
		}
	case "address":
		if s, ok := v.(string); !ok || !reHexAddr.MatchString(s) {
			return bad("address must be a 0x-prefixed 20-byte hex string")
		}
	case "bytes":
		if s, ok := v.(string); !ok || !strings.HasPrefix(s, "0x") || !reHexData.MatchString(s) {
			return bad("bytes must be 0x-prefixed even-length hex")
		}
	default:
		if signed, bits, ok := IntBits(t); ok {
			n, err := TypedInt(v)
			if err != nil {
				return bad("%s: %v", t, err)
			}
			lo, hi := new(big.Int), new(big.Int).Lsh(big.NewInt(1), uint(bits))
			if signed {
				hi.Rsh(hi, 1)
				lo.Neg(hi)
			}
			if n.Cmp(lo) < 0 || n.Cmp(hi) >= 0 {
				return bad("%s out of range", t)
			}
			return nil
		}
		n, _ := strconv.Atoi(strings.TrimPrefix(t, "bytes"))
		if s, ok := v.(string); !ok || len(s) != 2+2*n || !strings.HasPrefix(s, "0x") || !reHexData.MatchString(s) {
			return bad("%s must be 0x-prefixed hex of exactly %d bytes", t, n)
		}
	}
	return nil
}
