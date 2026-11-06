package signer

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/NikhilSetiya/stopbar/internal/decision"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// CodeAdapter is the reason code when the adapter refuses to sign, or the
// signed transaction cannot be committed.
const CodeAdapter = "FAIL_CLOSED_ADAPTER"

// Engine is the part of engine.Engine the gatekeeper drives.
type Engine interface {
	Evaluate(ctx context.Context, req model.ActionRequest) (model.Decision, error)
	Commit(ctx context.Context, requestID, txRef string) error
	Release(ctx context.Context, requestID, reason string) error
}

// Gatekeeper is gatekeeper mode (HLD §3): Stopbar holds the wallet key, so an
// allow comes back as a signed transaction. It implements gateway.Evaluator.
//
// allow → sign → commit the reservation (tx hash as the reference). If the
// adapter refuses, or the commit cannot be recorded, the reservation is
// released with the reason audited, the signed bytes are discarded, and the
// caller gets a deny.
type Gatekeeper struct {
	Engine  Engine
	Adapter *Adapter
	Logger  *slog.Logger
}

func (g *Gatekeeper) log() *slog.Logger {
	if g.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return g.Logger
}

func (g *Gatekeeper) Evaluate(ctx context.Context, req model.ActionRequest) (model.Decision, error) {
	d, err := g.Engine.Evaluate(ctx, req)
	if err != nil || d.Outcome != model.Allow {
		return d, err
	}
	raw, hash, err := g.Adapter.SignTx(ctx, d.Token, req.Action)
	if err != nil {
		reason := "adapter refused: " + adapterCode(err)
		g.log().Warn("gatekeeper: adapter refused an allow", "request_id", req.ID, "err", err)
		g.release(ctx, req.ID, reason)
		return refused(d), nil
	}
	if err := g.Engine.Commit(ctx, req.ID, hash.Hex()); err != nil {
		g.log().Error("gatekeeper: commit after signing failed; discarding the signed tx", "request_id", req.ID, "err", err)
		g.release(ctx, req.ID, "commit failed after signing; signed tx discarded")
		return refused(d), nil
	}
	d.SignedTx, d.TxHash = hexutil.Encode(raw), hash.Hex()
	return d, nil
}

func (g *Gatekeeper) release(ctx context.Context, id, reason string) {
	if err := g.Engine.Release(context.WithoutCancel(ctx), id, reason); err != nil {
		g.log().Warn("gatekeeper: release failed; the reservation lapses with its TTL", "request_id", id, "err", err)
	}
}

// adapterCode exposes the spec §4 code (or a fixed category), never internals.
func adapterCode(err error) string {
	var ve *decision.VerifyError
	switch {
	case errors.As(err, &ve):
		return ve.Code
	case errors.Is(err, ErrNoKey):
		return "NO_KEY_FOR_FROM"
	case errors.Is(err, ErrNotBindable):
		return "NOT_BINDABLE"
	case errors.Is(err, ErrDelegatedWallet):
		return "DELEGATED_WALLET"
	default:
		return "SIGNING_FAILED"
	}
}

// refused turns an allow the adapter would not sign into a deny.
func refused(d model.Decision) model.Decision {
	return model.Decision{
		RequestID: d.RequestID, Outcome: model.Deny,
		Reasons:          append(slices.Clone(d.Reasons), model.Reason{Code: CodeAdapter, Message: "signer adapter refused; failing closed"}),
		PolicyBundleHash: d.PolicyBundleHash, PayloadHash: d.PayloadHash,
		Approvals: []model.Approval{}, IssuedAt: d.IssuedAt, ExpiresAt: maxTime(d.ExpiresAt, d.IssuedAt.Add(time.Second)),
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
