// Package approval implements signed approvals (CS-151, spec/approval-signature-v1.md):
// Ed25519 approver keys, separate from API keys and decision keys, that
// countersign an escalation approval/reject or a circuit-breaker reset. The
// package is stdlib-only (part of the trusted core, like internal/decision)
// and has three layers:
//
//   - Key management: generating and loading approver key files (key.go),
//     and loading the server-side configuration of approver public keys
//     (config.go).
//   - Canonical objects and signing (object.go): the exact JCS-canonical
//     bytes an approver signs, domain-separated per object kind.
//   - Verification (verify.go) and quorum (quorum.go): checking one signed
//     envelope against the configured approvers and current state, and
//     tallying M-of-N distinct votes to a resolution.
//
// Nothing here persists state. Whatever stores pending escalations or
// breaker trips owns durability; this package owns only the cryptography
// and the counting rule.
package approval
