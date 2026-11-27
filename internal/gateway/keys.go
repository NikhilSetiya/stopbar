package gateway

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

// encoding/json matches object keys to struct fields case-insensitively, so
// {"to":"0xA…","To":"0xB…"} passes the (byte-exact) duplicate check and then
// silently decodes one of them. What the engine evaluates would then differ
// from the raw body that is audited and hashed. checkExactKeysAs closes that
// parser differential: every key must match a json tag exactly, at the
// position the struct defines. Free-form maps (action.args) are exempt; they
// are hashed verbatim and never decoded into fields.
//
// checkExactKeysAs checks body against the struct type t (a pointer is fine).
func checkExactKeysAs(body []byte, t reflect.Type) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return fail(CodeMalformedJSON, "%v", err)
	}
	return walkKeys(v, t, "")
}

var timeType = reflect.TypeOf(time.Time{})

func walkKeys(v any, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if t == timeType {
			return nil
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return nil // type mismatch: strict decode reports it
		}
		fields := jsonFields(t)
		for k, child := range obj {
			ft, ok := fields[k]
			if !ok {
				for name := range fields {
					if strings.EqualFold(name, k) {
						return fail(CodeUnknownField, "field %q at %s must be spelled %q", k, orRoot(path), name)
					}
				}
				return fail(CodeUnknownField, "unknown field %q at %s", k, orRoot(path))
			}
			if err := walkKeys(child, ft, join(path, k)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if arr, ok := v.([]any); ok {
			for _, el := range arr {
				if err := walkKeys(el, t.Elem(), path+"[]"); err != nil {
					return err
				}
			}
		}
	case reflect.Map: // typed_data.types values are structs; args values are any
		if obj, ok := v.(map[string]any); ok {
			for k, child := range obj {
				if err := walkKeys(child, t.Elem(), join(path, k)); err != nil {
					return err
				}
			}
		}
	}
	// Free-form maps (action.args, typed_data domain/message) and scalars:
	// no struct keys to check.
	return nil
}

func jsonFields(t reflect.Type) map[string]reflect.Type {
	m := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		m[name] = f.Type
	}
	return m
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func orRoot(path string) string {
	if path == "" {
		return "top level"
	}
	return path
}
