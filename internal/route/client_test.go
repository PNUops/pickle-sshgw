package route

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newServer spins a mock pickle-api that captures the raw request body and
// replies with the given status/body.
func newServer(t *testing.T, status int, body string, capture *[]byte, gotAuth *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/sshgw/route" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if gotAuth != nil {
			*gotAuth = r.Header.Get("Authorization")
		}
		if capture != nil {
			raw, _ := io.ReadAll(r.Body)
			*capture = raw
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
}

func mustClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: base, Token: "test-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestResolve_PublicKey_RequestShapeAndAuth(t *testing.T) {
	var raw []byte
	var auth string
	srv := newServer(t, 200,
		`{"ip":"172.29.4.11","port":22,"user":"student","hostKeys":["ssh-ed25519 AAAAC3Nza"]}`,
		&raw, &auth)
	defer srv.Close()

	r, err := mustClient(t, srv.URL).Resolve(context.Background(), Request{
		Slug: "team-alpha-a1b2", SourceIP: "203.0.113.7",
		AuthMethod: AuthPublicKey, PublicKeyFingerprint: "SHA256:abc", ConnectionID: "conn-1",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.IP != "172.29.4.11" || r.Port != 22 || r.User != "student" {
		t.Fatalf("bad route: %+v", r)
	}
	if len(r.HostKeys) != 1 || r.HostKeys[0] != "ssh-ed25519 AAAAC3Nza" {
		t.Fatalf("bad hostKeys: %+v", r.HostKeys)
	}
	if auth != "Bearer test-token" {
		t.Fatalf("bad auth header: %q", auth)
	}

	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("unmarshal captured body: %v", err)
	}
	if req.Slug != "team-alpha-a1b2" || req.SourceIP != "203.0.113.7" ||
		req.AuthMethod != "publickey" || req.PublicKeyFingerprint != "SHA256:abc" ||
		req.ConnectionID != "conn-1" {
		t.Fatalf("bad request body: %+v", req)
	}
	// authMethod must always be present on the wire.
	if !strings.Contains(string(raw), `"authMethod":"publickey"`) {
		t.Fatalf("authMethod missing from wire body: %s", raw)
	}
}

// The password path sends no fingerprint; omitempty must drop the field so the
// wire body matches the contract (fingerprint only on the publickey path).
func TestResolve_Password_OmitsFingerprint(t *testing.T) {
	var raw []byte
	srv := newServer(t, 200,
		`{"ip":"172.29.4.11","port":22,"user":"student","hostKeys":["ssh-ed25519 AAAAC3Nza"]}`,
		&raw, nil)
	defer srv.Close()

	_, err := mustClient(t, srv.URL).Resolve(context.Background(), Request{
		Slug: "slug", SourceIP: "203.0.113.7", AuthMethod: AuthPassword,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strings.Contains(string(raw), "publicKeyFingerprint") {
		t.Errorf("publicKeyFingerprint must be omitted on password path: %s", raw)
	}
	if strings.Contains(string(raw), "connectionId") {
		t.Errorf("connectionId must be omitted when empty: %s", raw)
	}
	if !strings.Contains(string(raw), `"authMethod":"password"`) {
		t.Errorf("authMethod missing from wire body: %s", raw)
	}
}

func mustResolve(c *Client) (*Route, error) {
	return c.Resolve(context.Background(), Request{
		Slug: "slug", SourceIP: "203.0.113.7", AuthMethod: AuthPublicKey,
		PublicKeyFingerprint: "SHA256:abc", ConnectionID: "conn-1",
	})
}

func TestResolve_Denials(t *testing.T) {
	// Route-level denials carry {reason}; chain-level rejections carry {code}.
	// v2 adds the per-user identity reason codes.
	cases := []struct {
		name       string
		status     int
		body       string
		wantReason string
		wantCode   string
	}{
		{"gateway_disabled", 403, `{"reason":"SSHGW_GATEWAY_DISABLED"}`, "SSHGW_GATEWAY_DISABLED", ""},
		{"route_not_found", 404, `{"reason":"SSHGW_ROUTE_NOT_FOUND"}`, "SSHGW_ROUTE_NOT_FOUND", ""},
		{"vm_not_running", 403, `{"reason":"SSHGW_VM_NOT_RUNNING"}`, "SSHGW_VM_NOT_RUNNING", ""},
		{"vm_blocked", 403, `{"reason":"SSHGW_VM_BLOCKED"}`, "SSHGW_VM_BLOCKED", ""},
		{"key_unknown", 403, `{"reason":"SSHGW_KEY_UNKNOWN"}`, "SSHGW_KEY_UNKNOWN", ""},
		{"key_not_member", 403, `{"reason":"SSHGW_KEY_NOT_MEMBER"}`, "SSHGW_KEY_NOT_MEMBER", ""},
		{"password_disabled", 403, `{"reason":"SSHGW_PASSWORD_DISABLED"}`, "SSHGW_PASSWORD_DISABLED", ""},
		{"no_host_key", 403, `{"reason":"SSHGW_NO_HOST_KEY"}`, "SSHGW_NO_HOST_KEY", ""},
		{"no_address", 403, `{"reason":"SSHGW_ROUTE_NO_ADDRESS"}`, "SSHGW_ROUTE_NO_ADDRESS", ""},
		{"token_invalid", 401, `{"code":"AUTH_TOKEN_INVALID"}`, "", "AUTH_TOKEN_INVALID"},
		{"access_denied", 403, `{"code":"ACCESS_DENIED"}`, "", "ACCESS_DENIED"},
		{"rate_limited", 429, `{"code":"RATE_LIMITED"}`, "", "RATE_LIMITED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, tc.status, tc.body, nil, nil)
			defer srv.Close()

			r, err := mustResolve(mustClient(t, srv.URL))
			if r != nil {
				t.Fatalf("expected nil route, got %+v", r)
			}
			var d *Denial
			if !errors.As(err, &d) {
				t.Fatalf("expected *Denial, got %v (%T)", err, err)
			}
			if d.HTTPStatus != tc.status {
				t.Errorf("status: got %d want %d", d.HTTPStatus, tc.status)
			}
			if d.Reason != tc.wantReason || d.Code != tc.wantCode {
				t.Errorf("reason/code: got (%q,%q) want (%q,%q)", d.Reason, d.Code, tc.wantReason, tc.wantCode)
			}
			// Machine() returns the single discriminator for logging.
			want := tc.wantReason
			if want == "" {
				want = tc.wantCode
			}
			if d.Machine() != want {
				t.Errorf("Machine(): got %q want %q", d.Machine(), want)
			}
		})
	}
}

func TestResolve_BadStatusIsGenericError(t *testing.T) {
	srv := newServer(t, 500, `boom`, nil, nil)
	defer srv.Close()

	_, err := mustResolve(mustClient(t, srv.URL))
	if err == nil {
		t.Fatal("expected error on 500")
	}
	var d *Denial
	if errors.As(err, &d) {
		t.Fatalf("500 must be a generic error, not a *Denial: %v", err)
	}
}

func TestResolve_Malformed200IsError(t *testing.T) {
	srv := newServer(t, 200, `{"ip":"","port":0,"user":"","hostKeys":[]}`, nil, nil)
	defer srv.Close()

	if _, err := mustResolve(mustClient(t, srv.URL)); err == nil {
		t.Fatal("expected error on empty 200 body")
	}
}

// A 200 with a valid target but no pinned host keys must be rejected: the
// gateway may not pipe to a host it cannot verify.
func TestResolve_EmptyHostKeysFailsClosed(t *testing.T) {
	srv := newServer(t, 200, `{"ip":"172.29.4.11","port":22,"user":"student","hostKeys":[]}`, nil, nil)
	defer srv.Close()

	_, err := mustResolve(mustClient(t, srv.URL))
	if err == nil {
		t.Fatal("expected error when hostKeys is empty")
	}
	var d *Denial
	if errors.As(err, &d) {
		t.Fatalf("empty hostKeys must be a generic error, not a *Denial: %v", err)
	}
}

func TestResolve_TransportErrorFailsClosed(t *testing.T) {
	// Nothing listening: the client must return an error, never a route.
	c := mustClient(t, "http://127.0.0.1:1") // unroutable/refused
	if _, err := mustResolve(c); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestSessionStart_PostsAuditRequest(t *testing.T) {
	var raw []byte
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/sshgw/session" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := mustClient(t, srv.URL).SessionStart(context.Background(), SessionRequest{
		Slug: "team-alpha-a1b2", SourceIP: "203.0.113.7", AuthMethod: AuthPublicKey,
		CandidateFingerprints: []string{"SHA256:abc", "SHA256:def"}, ConnectionID: "conn-1",
	})
	if err != nil {
		t.Fatalf("SessionStart: %v", err)
	}
	if auth != "Bearer test-token" {
		t.Errorf("bad auth header: %q", auth)
	}
	var got SessionRequest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ConnectionID != "conn-1" || len(got.CandidateFingerprints) != 2 ||
		got.CandidateFingerprints[0] != "SHA256:abc" || got.CandidateFingerprints[1] != "SHA256:def" {
		t.Errorf("bad session body: %+v", got)
	}
}

// The password path sends no candidateFingerprints (omitempty drops the field).
func TestSessionStart_PasswordOmitsCandidates(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	if err := mustClient(t, srv.URL).SessionStart(context.Background(), SessionRequest{
		Slug: "slug", SourceIP: "203.0.113.7", AuthMethod: AuthPassword, ConnectionID: "conn-1",
	}); err != nil {
		t.Fatalf("SessionStart: %v", err)
	}
	if strings.Contains(string(raw), "candidateFingerprints") {
		t.Errorf("password session must omit candidateFingerprints: %s", raw)
	}
}

func TestSessionStart_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := mustClient(t, srv.URL).SessionStart(context.Background(), SessionRequest{AuthMethod: AuthPassword}); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestSessionStart_TransportError(t *testing.T) {
	if err := mustClient(t, "http://127.0.0.1:1").SessionStart(context.Background(), SessionRequest{AuthMethod: AuthPassword}); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestConfigValidate_FailClosed(t *testing.T) {
	if _, err := New(Config{BaseURL: "", Token: "t"}); err == nil {
		t.Error("empty BaseURL must fail")
	}
	if _, err := New(Config{BaseURL: "http://x", Token: ""}); err == nil {
		t.Error("empty Token must fail (PICKLE_SSHGW_TOKEN unset)")
	}
	if _, err := New(Config{BaseURL: "http://x", Token: "  "}); err == nil {
		t.Error("whitespace Token must fail")
	}
}
