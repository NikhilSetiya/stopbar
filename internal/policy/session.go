package policy

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

// SessionTaint is the enricher that gives tool calls session-level
// (context) taint (LLD §8.2), driven only by the bundle's frozen trust map.
//
// A session is tainted from the moment Stopbar evaluates a call to an
// untrusted-output tool: that output then enters the agent's context. The
// call itself is not tainted by its own output. Labels come from Stopbar,
// not from the caller, so a runner cannot change what counts as untrusted.
// It only names the session (actor.session_id). Taint only restricts:
// recording at evaluation time over-taints a call that is later denied,
// never under-taints.
type SessionTaint struct {
	Bundle *Bundle
	TTL    time.Duration // idle sessions are forgotten after this (default 24h)
	Clock  func() time.Time

	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	tainted  bool
	lastSeen time.Time
}

// Enrich implements engine.Enricher.
func (s *SessionTaint) Enrich(_ context.Context, er *model.EnrichedRequest) error {
	if er.Request.Action.Kind != model.KindToolCall {
		return nil
	}
	trust := s.Bundle.Trust()
	if trust == nil {
		return errors.New("policy: session taint needs a bundle with a tool trust map")
	}
	a := er.Request.Actor
	if a.SessionID == "" {
		return errors.New("policy: tool calls need actor.session_id for session taint; failing closed")
	}
	key := strconv.Quote(er.Request.Tenant) + "/" + strconv.Quote(a.AgentID) + "/" + strconv.Quote(a.SessionID)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]*session{}
	}
	s.prune(now)
	sess, ok := s.sessions[key]
	if !ok {
		sess = &session{}
		s.sessions[key] = sess
	}
	sess.lastSeen = now
	if sess.tainted && !slices.Contains(er.Taint, UntrustedToolOutput) {
		er.Taint = append(er.Taint, UntrustedToolOutput)
	}
	if er.Request.Action.Tool != nil && slices.Contains(trust.UntrustedOutputTools, *er.Request.Action.Tool) {
		sess.tainted = true // this call's output enters the context from here on
	}
	return nil
}

func (s *SessionTaint) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

func (s *SessionTaint) prune(now time.Time) {
	ttl := s.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	for k, v := range s.sessions {
		if now.Sub(v.lastSeen) > ttl {
			delete(s.sessions, k)
		}
	}
}
