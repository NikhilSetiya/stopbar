package model

import "slices"

// Clone returns a deep copy of r: no pointer, slice or map (Args included) is
// shared with r, so a component working on the copy (a timed-out engine
// stage, CS-197) can never change r or race a reader of it.
func (r ActionRequest) Clone() ActionRequest {
	c := r
	c.Action = r.Action.Clone()
	c.ParentRequestID = clonePtr(r.ParentRequestID)
	c.Provenance.Labels = slices.Clone(r.Provenance.Labels)
	c.Provenance.Sources = slices.Clone(r.Provenance.Sources)
	c.Provenance.SDK = clonePtr(r.Provenance.SDK)
	return c
}

// Clone returns a deep copy of a (see ActionRequest.Clone).
func (a Action) Clone() Action {
	c := a
	c.ChainID = clonePtr(a.ChainID)
	c.TxType = clonePtr(a.TxType)
	c.Tool = clonePtr(a.Tool)
	if a.Args != nil {
		c.Args = cloneValue(a.Args).(map[string]any)
	}
	return c
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// cloneValue deep-copies a JSON-shaped value (maps, slices, scalars).
func cloneValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = cloneValue(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = cloneValue(e)
		}
		return s
	default:
		return v
	}
}
