// Package toolcall decodes tool-call actions (CS-502). There is no calldata
// to interpret: the intent is the tool and its arguments, which policy sees
// through the bundle's trust map.
package toolcall

import (
	"context"
	"fmt"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// Decoder implements engine.Decoder for tool calls.
type Decoder struct{}

func (Decoder) Supports(a model.Action) bool { return a.Kind == model.KindToolCall }

func (Decoder) Decode(_ context.Context, a model.Action) (model.IntentSummary, error) {
	if a.Tool == nil || *a.Tool == "" {
		return model.IntentSummary{}, fmt.Errorf("toolcall: no tool name")
	}
	return model.IntentSummary{Kind: "tool_call", Destination: *a.Tool, Flags: []string{},
		Human: fmt.Sprintf("Call tool %s with %d argument(s)", *a.Tool, len(a.Args))}, nil
}
