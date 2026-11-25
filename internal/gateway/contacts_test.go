package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NikhilSetiya/stopbar/internal/approval"
	"github.com/NikhilSetiya/stopbar/internal/auth"
	"github.com/NikhilSetiya/stopbar/internal/model"
)

// fakeContacts records what the gateway passed and returns err.
type fakeContacts struct {
	tenant, by, kid string
	pending         bool // Approve: the vote is recorded, quorum not met
	err             error
}

func (f *fakeContacts) c(tenant string, by auth.Identity) (model.Contact, error) {
	f.tenant, f.by = tenant, by.KeyID
	return model.Contact{ID: "ct_1", Tenant: tenant, SimilarTo: []model.SimilarContact{}}, f.err
}
func (f *fakeContacts) Request(t, _, _ string, by auth.Identity, _ time.Time) (model.Contact, error) {
	return f.c(t, by)
}
func (f *fakeContacts) Approve(t, _ string, sig approval.SignedContact, by auth.Identity, _ time.Time) (model.Contact, error) {
	f.kid = sig.Kid
	c, err := f.c(t, by)
	if !f.pending {
		at := time.Now()
		c.ApprovedAt, c.ActiveFrom = &at, &at
	}
	return c, err
}
func (f *fakeContacts) Remove(t, _ string, by auth.Identity, _ time.Time) (model.Contact, error) {
	return f.c(t, by)
}
func (f *fakeContacts) List(t string, _ time.Time) ([]model.Contact, error) {
	c, err := f.c(t, auth.Identity{})
	return []model.Contact{c}, err
}

// The /v1/contacts routes (CS-134): tenant and identity come from the
// credential; scopes, strict body checks and registry errors map to typed
// codes; with no registry or no auth the API is off.
func TestContactsRoutes(t *testing.T) {
	const addr = "0x7a25a1c4e3b2d1f09876543210fedcba98760c21"
	ksContacts := keyStore(t, "sk", "acme", "ops", ContactsScope)
	ksApprove := keyStore(t, "sk", "acme", "alice", ApproveScope)
	ksEval := keyStore(t, "sk", "acme", "bot", EvalScope)
	// The gateway only decodes the envelope; the registry verifies it.
	sig := `{"tenant":"acme","contact_id":"ct_1","address":"` + addr + `","decision":"approve","expiry":1,"kid":"kid_alice","sig":"AA"}`
	for _, tt := range []struct {
		name, method, path, body string
		ks                       *auth.KeyStore
		noContacts, pending      bool
		regErr                   error
		status                   int
		code                     Code
	}{
		{"request: 202, tenant from the key", "POST", "/v1/contacts", `{"address":"` + addr + `","label":"v"}`, ksContacts, false, false, nil, 202, ""},
		{"request: unknown field", "POST", "/v1/contacts", `{"address":"` + addr + `","tenant":"evil"}`, ksContacts, false, false, nil, 400, CodeUnknownField},
		{"request: wrong-case key", "POST", "/v1/contacts", `{"Address":"` + addr + `"}`, ksContacts, false, false, nil, 400, CodeUnknownField},
		{"request: bad address", "POST", "/v1/contacts", `{"address":"0x12"}`, ksContacts, false, false, nil, 400, CodeInvalidRequest},
		{"request: duplicate", "POST", "/v1/contacts", `{"address":"` + addr + `"}`, ksContacts, false, false, model.ErrContactExists, 409, CodeConflict},
		{"request: approve scope is not enough", "POST", "/v1/contacts", `{"address":"` + addr + `"}`, ksApprove, false, false, nil, 403, CodeForbiddenScope},
		{"approve: quorum met, 200", "POST", "/v1/contacts/ct_1/approve", sig, ksApprove, false, false, nil, 200, ""},
		{"approve: vote recorded, quorum not met, 202", "POST", "/v1/contacts/ct_1/approve", sig, ksApprove, false, true, nil, 202, ""},
		{"approve: any scope may carry the signature", "POST", "/v1/contacts/ct_1/approve", sig, ksEval, false, false, nil, 200, ""},
		{"approve: no signed envelope", "POST", "/v1/contacts/ct_1/approve", "", ksApprove, false, false, nil, 400, CodeMalformedJSON},
		{"approve: unknown envelope field", "POST", "/v1/contacts/ct_1/approve", strings.Replace(sig, `"sig"`, `"by":"x","sig"`, 1), ksApprove, false, false, nil, 400, CodeInvalidRequest},
		{"approve: bad signature", "POST", "/v1/contacts/ct_1/approve", sig, ksApprove, false, false, &approval.VerifyError{Code: approval.CodeBadSignature}, 400, CodeInvalidSignature},
		{"approve: same owner twice", "POST", "/v1/contacts/ct_1/approve", sig, ksApprove, false, false, model.ErrDuplicateVote, 409, CodeDuplicateVote},
		{"approve: self", "POST", "/v1/contacts/ct_1/approve", sig, ksApprove, false, false, model.ErrSelfApproval, 403, CodeSelfApproval},
		{"approve: unknown id", "POST", "/v1/contacts/ct_x/approve", sig, ksApprove, false, false, model.ErrNoContact, 404, CodeNotFound},
		{"approve: already approved", "POST", "/v1/contacts/ct_1/approve", sig, ksApprove, false, false, model.ErrContactApproved, 409, CodeConflict},
		{"approve: registry down", "POST", "/v1/contacts/ct_1/approve", sig, ksApprove, false, false, errors.New("disk"), 500, CodeInternal},
		{"remove: 200", "DELETE", "/v1/contacts/" + addr, "", ksContacts, false, false, nil, 200, ""},
		{"remove: bad address", "DELETE", "/v1/contacts/0x12", "", ksContacts, false, false, nil, 400, CodeInvalidRequest},
		{"list: contacts scope", "GET", "/v1/contacts", "", ksContacts, false, false, nil, 200, ""},
		{"list: approve scope", "GET", "/v1/contacts", "", ksApprove, false, false, nil, 200, ""},
		{"wrong method: typed 405", "PUT", "/v1/contacts", "", ksContacts, false, false, nil, 405, CodeMethodNotAllowed},
		{"no credential", "GET", "/v1/contacts", "", ksContacts, false, false, nil, 401, CodeUnauthenticated},
		{"auth off: API off", "GET", "/v1/contacts", "", nil, false, false, nil, 503, CodeEngineUnavailable},
		{"no registry: API off", "GET", "/v1/contacts", "", ksContacts, true, false, nil, 503, CodeEngineUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeContacts{err: tt.regErr, pending: tt.pending}
			cfg := Config{}
			if tt.ks != nil {
				cfg.Authenticator = BearerAuthenticator{Store: tt.ks}
			}
			if !tt.noContacts {
				cfg.Contacts = fc
			}
			var audited []string
			cfg.Audit = auditFunc(func(_ context.Context, ty model.AuditRecordType, b any) error {
				audited = append(audited, string(ty)+":"+b.(map[string]any)["reason"].(string))
				return nil
			})
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.name != "no credential" {
				req.Header.Set("Authorization", "Bearer sk")
			}
			rec := httptest.NewRecorder()
			New(cfg).ServeHTTP(rec, req)
			res := rec.Result()
			b, _ := io.ReadAll(res.Body)
			if res.StatusCode != tt.status {
				t.Fatalf("status %d, want %d: %s", res.StatusCode, tt.status, b)
			}
			if tt.code != "" {
				var e ErrorBody
				if json.Unmarshal(b, &e) != nil || e.Code != tt.code {
					t.Fatalf("body %s, want code %s", b, tt.code)
				}
			}
			if tt.status == 405 && res.Header.Get("Allow") != "GET, POST" {
				t.Fatalf("Allow %q", res.Header.Get("Allow"))
			}
			if tt.status/100 == 2 && tt.method != "GET" && (fc.tenant != "acme" || fc.by != "ak_demo") {
				t.Fatalf("registry got tenant %q by %q, want the key's", fc.tenant, fc.by)
			}
			if strings.HasSuffix(tt.path, "/approve") && tt.status/100 == 2 && fc.kid != "kid_alice" {
				t.Fatalf("registry got kid %q, want the envelope's", fc.kid)
			}
			// Missing scopes and self-approvals are audited.
			wantAudit := tt.code == CodeForbiddenScope || errors.Is(tt.regErr, model.ErrSelfApproval)
			if (len(audited) == 1) != wantAudit || (wantAudit && !strings.HasPrefix(audited[0], "auth_reject:")) {
				t.Fatalf("audited %v, want audit=%v", audited, wantAudit)
			}
		})
	}
}
