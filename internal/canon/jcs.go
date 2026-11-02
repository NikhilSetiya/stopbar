// Package canon implements RFC 8785 JSON Canonicalization Scheme (JCS) and the
// hashing helpers built on it. It is stdlib-only on purpose: everything that
// feeds a hash or a signature sits in the trusted core and carries no
// third-party dependencies.
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInvalidNumber is returned for NaN, ±Inf, or numbers that overflow float64.
var ErrInvalidNumber = errors.New("canon: number not representable as IEEE-754 double")

// ErrDuplicateKey is returned when an object contains the same member name twice.
// RFC 8785 requires I-JSON input (RFC 7493), which forbids duplicates.
var ErrDuplicateKey = errors.New("canon: duplicate object key")

// Transform canonicalises raw JSON bytes per RFC 8785.
func Transform(in []byte) ([]byte, error) {
	if !utf8.Valid(in) {
		return nil, errors.New("canon: input is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	var buf bytes.Buffer
	if err := writeValue(&buf, dec); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("canon: trailing data after JSON value")
	}
	return buf.Bytes(), nil
}

// Marshal encodes v with encoding/json and canonicalises the result.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Transform(raw)
}

func writeValue(buf *bytes.Buffer, dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return writeObject(buf, dec)
		case '[':
			return writeArray(buf, dec)
		}
		return fmt.Errorf("canon: unexpected delimiter %q", t)
	case string:
		writeString(buf, t)
	case json.Number:
		s, err := FormatNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("canon: unexpected token %T", tok)
	}
	return nil
}

type member struct {
	key   string
	value []byte
}

func writeObject(buf *bytes.Buffer, dec *json.Decoder) error {
	var members []member
	seen := map[string]struct{}{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := kt.(string)
		if !ok {
			return errors.New("canon: object key is not a string")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
		}
		seen[key] = struct{}{}
		var vb bytes.Buffer
		if err := writeValue(&vb, dec); err != nil {
			return err
		}
		members = append(members, member{key, vb.Bytes()})
	}
	if _, err := dec.Token(); err != nil { // consume '}'
		return err
	}
	// RFC 8785 §3.2.3: sort by UTF-16 code units, not bytes or runes.
	sort.Slice(members, func(i, j int) bool { return lessUTF16(members[i].key, members[j].key) })
	buf.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeString(buf, m.key)
		buf.WriteByte(':')
		buf.Write(m.value)
	}
	buf.WriteByte('}')
	return nil
}

func writeArray(buf *bytes.Buffer, dec *json.Decoder) error {
	buf.WriteByte('[')
	for i := 0; dec.More(); i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeValue(buf, dec); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // consume ']'
		return err
	}
	buf.WriteByte(']')
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString serialises per RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify rules).
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// FormatNumber renders a JSON number literal using the ECMAScript
// Number.prototype.toString algorithm (ECMA-262 §7.1.12.1), as RFC 8785 requires.
func FormatNumber(lit string) (string, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: %s", ErrInvalidNumber, lit)
	}
	return formatES(f), nil
}

func formatES(f float64) string {
	if f == 0 {
		return "0" // covers -0
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// Shortest round-trip digits: d.ddddde±XX
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	k := len(digits)
	n := exp + 1 // position of decimal point relative to digits

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		ev := n - 1
		if ev < 0 {
			ev = -ev
		}
		if k == 1 {
			out = digits + "e" + es + strconv.Itoa(ev)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(ev)
		}
	}
	return sign + out
}
