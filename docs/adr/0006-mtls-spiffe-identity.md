# ADR 0006: mTLS client identity from a SPIFFE ID, mapped by operator configuration

- Status: **Accepted**
- Date: 2026-11-25
- Task: CS-103, increment 3 of 3 (issue #12)
- Builds on: [ADR 0003](0003-decision-token-v2-identity.md) (decision token v2 binds `auth_method`, `key_id`, `agent_id`)

## Context

Increments 1 and 2 made identity come from authentication alone and bound it
into every audit record and decision token. The only credential was an API
key, a bearer secret that LLD §4 limits to sidecar and dev use. Service mode
(HLD §6: a separate container or VM the agent reaches over the network) needs
a credential that is not a replayable secret in a header and that fits
workload-identity systems (SPIFFE/SPIRE, service meshes, an internal CA). PRD
FR-PRV-3 asks for workload identity on requests.

## Decision

1. **stopbard serves TLS 1.3 only with client-certificate authentication.**
   `-tls-cert`, `-tls-key`, `-tls-client-ca` and `-mtls-identities` (config:
   `tls_cert`, `tls_key`, `tls_client_ca`, `mtls_identities`) go together.
   stopbard refuses to start on any partial set, so there is no TLS without a
   client CA and no client CA without TLS. It also refuses a server key that is
   group- or world-readable, a server certificate that is not valid now, a
   client-CA file holding anything other than certificates, and mTLS combined
   with `-auth-keys`. A deployment has one identity source, so a request is
   never authenticated two ways with two answers.
2. **The identity is the certificate's single SPIFFE ID URI SAN** (X.509-SVID
   rules): exactly one URI SAN, in canonical form
   (`spiffe://<trust-domain>/<path>`: lowercase trust domain, no port,
   userinfo, query, fragment, percent-encoding, or empty, `.` or `..` path
   segments), on a leaf that is not a CA and has the client-auth EKU.
   Subject CNs and DNS SANs are ignored.
3. **Tenant, agent and scopes come from operator configuration, never the
   certificate.** `-mtls-identities` is a JSON array of `{spiffe_id, tenant,
   agent_id, scopes}`. An unmapped SPIFFE ID is unauthenticated. A CA that can
   issue certificates for a trust domain cannot also grant scopes or pick a
   tenant: the operator decides that per workload, the same way an API key
   record does. Revocation is removing the entry (and short certificate
   lifetimes, as SPIRE issues them).
4. **Verification happens twice, both with crypto/x509 only.** The handshake
   (`tls.VerifyClientCertIfGiven` against the client CA) refuses a certificate
   that is expired or from another CA before any HTTP is read. The
   authenticator (`auth.CertMap.Identify`) then verifies the chain again, with
   the client-auth EKU, so the mapping is sound by itself and not only when the
   listener is configured correctly. A client with no certificate completes the
   handshake, so `/healthz`, `/metrics` and `/v1/keys` stay reachable, and gets
   `401 UNAUTHENTICATED` on every authenticated route. An unmapped or SAN-less
   certificate gets 401 as well.
5. **The resulting `auth.Identity` is `{method: mtls, tenant, agent_id, scopes,
   key_id: <SPIFFE ID>}`.** Everything downstream is unchanged: the body's
   tenant and agent must match (`IDENTITY_MISMATCH`), and under mTLS so must a
   body `actor.workload_identity`, if one is set. Every audit record carries the
   identity, the per-identity rate limit keys on the SPIFFE ID, and the decision
   token binds `auth_method` = `mtls` and `key_id` = the SPIFFE ID. The
   gatekeeper adapter checks those against the request it signs (decision-token
   v2 §4 step 7d).
6. **Clients present certificates.** `stopbar approve|reject|breaker|contacts`
   take `--cert`, `--cert-key` and `--cacert`. The Python SDK takes
   `client_cert`, `client_key` and `ca_cert` (stdlib `ssl`). The TypeScript SDK
   takes `tls: {cert, key, ca}` and uses `node:https`, because global fetch
   cannot present a client certificate. Neither SDK gains a dependency.

## Consequences

- **The non-loopback listen gate (CS-103) is satisfied by mTLS** as well as by
  API keys.
- **No token or spec version change.** decision-token-v2 already defined `mtls`
  and has an `allow_mtls` vector (ADR 0003). Only the `key_id` wording in the
  spec now names the SPIFFE ID.
- **Certificate issuance and rotation are the operator's job** (SPIRE, a mesh
  or an internal CA). stopbard reads its files at start, so rotating the server
  certificate, the client CA or the identity map means a restart. Client
  certificates rotate freely, since the map keys on the SPIFFE ID, not the
  certificate.
- **Threat tiers are unchanged.** As with API keys, a compromised requester
  holding its own certificate is still that caller (T3). mTLS removes the
  bearer secret, which can be replayed from a log or a header, and binds the
  credential to a key that never crosses the wire.
- **What is not done:** SPIFFE federation bundles and the Workload API (stopbard
  takes a static CA file), and CRL/OCSP checking (short-lived SVIDs and removal
  from the map are the revocation path).
