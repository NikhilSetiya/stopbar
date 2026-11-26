package model

import (
	"errors"
	"strings"
	"testing"
)

func typedFixture(t *testing.T) ActionRequest {
	t.Helper()
	return roundTrip[ActionRequest](t, "../../spec/fixtures/action_request.evm_typed_data.json")
}

func msg(td *TypedData) map[string]any { return td.Message["details"].(map[string]any) }

func TestTypedDataValidate(t *testing.T) {
	cases := map[string]struct {
		mut  func(*Action)
		want []string // every problem expected, reported at once
	}{
		"ok":                      {func(*Action) {}, nil},
		"json number within 2^53": {func(a *Action) { msg(a.TypedData)["nonce"] = float64(7) }, nil},
		"no typed data":           {func(a *Action) { a.TypedData = nil }, []string{"typed_data is required"}},
		"tx fields":               {func(a *Action) { a.To, a.GasLimit = "0x3333333333333333333333333333333333333333", "1" }, []string{"carries no transaction"}},
		"message on typed data":   {func(a *Action) { a.Message = "0x00" }, []string{"evm_personal_sign only"}},
		"no chain":                {func(a *Action) { a.ChainID = nil }, []string{"chain_id is required"}},
		"chain mismatch":          {func(a *Action) { a.TypedData.Domain["chainId"] = "1" }, []string{"does not match action.chain_id"}},
		"no chainId in domain": {func(a *Action) {
			a.TypedData.Types[DomainType] = a.TypedData.Types[DomainType][:1]
			a.TypedData.Domain = map[string]any{"name": "Permit2"}
		}, []string{"domain.chainId is required"}},
		"domain out of order": {func(a *Action) {
			d := a.TypedData.Types[DomainType]
			d[0], d[1] = d[1], d[0]
		}, []string{"standard order"}},
		"domain extra member":   {func(a *Action) { a.TypedData.Domain["version"] = "1" }, []string{`"version" is not a member`}},
		"domain empty name":     {func(a *Action) { a.TypedData.Domain["name"] = "" }, []string{"domain.name must not be empty"}},
		"hex integer":           {func(a *Action) { msg(a.TypedData)["amount"] = "0xff" }, []string{"not a decimal integer"}},
		"leading zero integer":  {func(a *Action) { msg(a.TypedData)["amount"] = "01" }, []string{"not a decimal integer"}},
		"fractional number":     {func(a *Action) { msg(a.TypedData)["amount"] = 1.5 }, []string{"not an integer"}},
		"uint160 overflow":      {func(a *Action) { msg(a.TypedData)["amount"] = "1461501637330902918203684832716283019655932542976" }, []string{"uint160 out of range"}},
		"negative uint":         {func(a *Action) { msg(a.TypedData)["nonce"] = "-1" }, []string{"uint48 out of range"}},
		"bad address":           {func(a *Action) { a.TypedData.Message["spender"] = "0x12" }, []string{"address must be"}},
		"missing member":        {func(a *Action) { delete(a.TypedData.Message, "sigDeadline") }, []string{"sigDeadline is missing"}},
		"extra member":          {func(a *Action) { a.TypedData.Message["extra"] = "1" }, []string{`"extra" is not a member`}},
		"struct not object":     {func(a *Action) { a.TypedData.Message["details"] = "x" }, []string{"must be a JSON object"}},
		"undeclared type":       {func(a *Action) { a.TypedData.Types["PermitSingle"][0].Type = "Nope" }, []string{`type "Nope" is not atomic`}},
		"bare uint":             {func(a *Action) { a.TypedData.Types["PermitDetails"][1].Type = "uint" }, []string{`type "uint" is not atomic`}},
		"primary is domain":     {func(a *Action) { a.TypedData.PrimaryType = DomainType }, []string{"primaryType"}},
		"primary undeclared":    {func(a *Action) { a.TypedData.PrimaryType = "Order" }, []string{"primaryType"}},
		"repeated field":        {func(a *Action) { a.TypedData.Types["PermitDetails"][1].Name = "token" }, []string{"invalid or repeated"}},
		"no message":            {func(a *Action) { a.TypedData.Message = nil }, []string{"message is required"}},
		"no domain type":        {func(a *Action) { delete(a.TypedData.Types, DomainType) }, []string{"EIP712Domain is required"}},
		"no types":              {func(a *Action) { a.TypedData.Types = nil }, []string{"types is required"}},
		"number beyond 2^53":    {func(a *Action) { msg(a.TypedData)["amount"] = float64(1 << 54) }, []string{"within ±2^53"}},
		"bool for integer":      {func(a *Action) { msg(a.TypedData)["amount"] = true }, []string{"decimal string or a JSON number"}},
		"several problems kept": {func(a *Action) { a.From = "x"; a.TypedData.Message["spender"] = 1.0 }, []string{"action.from", "address must be"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := typedFixture(t)
			c.mut(&r.Action)
			err := r.Validate()
			if len(c.want) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("err = %v, want a ValidationError", err)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("missing problem %q in %v", w, err)
				}
			}
		})
	}
}

func TestTypedDataValueShapes(t *testing.T) {
	td := TypedData{Types: map[string][]TypedField{"T": {
		{"b", "bool"}, {"s", "string"}, {"raw", "bytes"}, {"h", "bytes32"}, {"i", "int8"}, {"xs", "uint8[2]"}, {"ys", "T2[]"},
	}, "T2": {{"a", "address"}}}}
	ok := map[string]any{"b": true, "s": "x", "raw": "0x", "h": "0x" + strings.Repeat("ab", 32), "i": "-128",
		"xs": []any{"1", 2.0}, "ys": []any{map[string]any{"a": "0x2222222222222222222222222222222222222222"}}}
	if p := td.check("T", ok, "m", 0); len(p) != 0 {
		t.Fatal(p)
	}
	bad := map[string]any{"b": "true", "s": 1.0, "raw": "ab", "h": "0x00", "i": "128", "xs": []any{"1"}, "ys": "x"}
	if p := td.check("T", bad, "m", 0); len(p) != 7 {
		t.Fatalf("want 7 problems, got %d: %v", len(p), p)
	}
}

func TestPersonalSignValidate(t *testing.T) {
	r := roundTrip[ActionRequest](t, "../../spec/fixtures/action_request.evm_personal_sign.json")
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"", "0x", "0xabc", "abcd", "0xzz"} {
		r.Action.Message = m
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "action.message") {
			t.Errorf("message %q: err = %v", m, err)
		}
	}
	r.Action.Message, r.Action.TypedData = "0x01", &TypedData{}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "evm_typed_data only") {
		t.Errorf("typed_data on personal_sign: err = %v", err)
	}
}
