package canon

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

// RFC 8785 Appendix B: IEEE-754 bit patterns and their required serialisation.
var rfcNumberVectors = []struct{ bits, want string }{
	{"0000000000000000", "0"},
	{"8000000000000000", "0"},
	{"0000000000000001", "5e-324"},
	{"8000000000000001", "-5e-324"},
	{"7fefffffffffffff", "1.7976931348623157e+308"},
	{"ffefffffffffffff", "-1.7976931348623157e+308"},
	{"4340000000000000", "9007199254740992"},
	{"c340000000000000", "-9007199254740992"},
	{"4430000000000000", "295147905179352830000"},
	{"44b52d02c7e14af5", "9.999999999999997e+22"},
	{"44b52d02c7e14af6", "1e+23"},
	{"44b52d02c7e14af7", "1.0000000000000001e+23"},
	{"444b1ae4d6e2ef4e", "999999999999999700000"},
	{"444b1ae4d6e2ef4f", "999999999999999900000"},
	{"444b1ae4d6e2ef50", "1e+21"},
	{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
	{"3eb0c6f7a0b5ed8d", "0.000001"},
	{"41b3de4355555553", "333333333.3333332"},
	{"41b3de4355555554", "333333333.33333325"},
	{"41b3de4355555555", "333333333.3333333"},
	{"41b3de4355555556", "333333333.3333334"},
	{"41b3de4355555557", "333333333.33333343"},
	{"becbf647612f3696", "-0.0000033333333333333333"},
	{"43143ff3c1cb0959", "1424953923781206.2"},
}

func TestRFC8785NumberVectors(t *testing.T) {
	for _, v := range rfcNumberVectors {
		u, err := strconv.ParseUint(v.bits, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := formatES(math.Float64frombits(u)); got != v.want {
			t.Errorf("%s: got %s want %s", v.bits, got, v.want)
		}
	}
}

func TestRFC8785Example(t *testing.T) {
	// RFC 8785 §3.2.2 input and expected output.
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("\ngot  %s\nwant %s", got, want)
	}
}

func TestUTF16KeyOrdering(t *testing.T) {
	// RFC 8785 §3.2.3 sorting example: keys must sort by UTF-16 code units.
	in := `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("\ngot  %s\nwant %s", got, want)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]error{
		`{"a":1,"a":2}`: ErrDuplicateKey,
		`1e400`:         ErrInvalidNumber,
	}
	for in, want := range cases {
		if _, err := Transform([]byte(in)); !errors.Is(err, want) {
			t.Errorf("%s: got %v want %v", in, err, want)
		}
	}
	if _, err := Transform([]byte(`{} {}`)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := Transform([]byte{'"', 0xff, '"'}); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

func TestOrderAndWhitespaceIndependentHash(t *testing.T) {
	a, _ := Transform([]byte(`{"b":2,"a":{"y":[1,2],"x":"z"}}`))
	b, _ := Transform([]byte("{ \"a\" : { \"x\":\"z\", \"y\":[ 1 , 2.0 ] },\n \"b\" : 2e0 }"))
	if Digest(a) != Digest(b) {
		t.Fatalf("hash differs:\n%s\n%s", a, b)
	}
}

func TestRecordHashChains(t *testing.T) {
	body := map[string]any{"request_id": "req_1", "outcome": "deny"}
	h1, err := RecordHash(1, "2026-11-02T10:00:00Z", "decision", body, GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	h1b, _ := RecordHash(1, "2026-11-02T10:00:00Z", "decision", map[string]any{"outcome": "deny", "request_id": "req_1"}, GenesisHash)
	if h1 != h1b {
		t.Fatal("record hash depends on map order")
	}
	h2, _ := RecordHash(1, "2026-11-02T10:00:00Z", "decision", map[string]any{"request_id": "req_1", "outcome": "allow"}, GenesisHash)
	if h1 == h2 {
		t.Fatal("tampered body produced same hash")
	}
	h3, _ := RecordHash(2, "2026-11-02T10:00:01Z", "decision", body, h1)
	h3b, _ := RecordHash(2, "2026-11-02T10:00:01Z", "decision", body, h2)
	if h3 == h3b {
		t.Fatal("hash does not bind prev_hash")
	}
}

func FuzzTransformIdempotent(f *testing.F) {
	for _, s := range []string{`{"a":[1,2.5,-0,1e21]}`, `"x\u0001"`, `[{"\u00e9":null}]`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c1, err := Transform([]byte(s))
		if err != nil {
			return
		}
		c2, err := Transform(c1)
		if err != nil {
			t.Fatalf("canonical output rejected: %s: %v", c1, err)
		}
		if string(c1) != string(c2) {
			t.Fatalf("not idempotent: %s -> %s", c1, c2)
		}
	})
}
