package route

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newServer spins a mock pickle-api that captures the request and replies with
// the given status/body.
func newServer(t *testing.T, status int, body string, capture *routeRequest, gotAuth *string) *httptest.Server {
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
			_ = json.Unmarshal(raw, capture)
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

func TestResolve_Success_RequestShapeAndAuth(t *testing.T) {
	var req routeRequest
	var auth string
	srv := newServer(t, 200, `{"ip":"172.29.4.11","port":22,"user":"student"}`, &req, &auth)
	defer srv.Close()

	r, err := mustClient(t, srv.URL).Resolve(context.Background(), "team-alpha-a1b2", "203.0.113.7")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.IP != "172.29.4.11" || r.Port != 22 || r.User != "student" {
		t.Fatalf("bad route: %+v", r)
	}
	if req.Slug != "team-alpha-a1b2" || req.SourceIP != "203.0.113.7" {
		t.Fatalf("bad request body: %+v", req)
	}
	if auth != "Bearer test-token" {
		t.Fatalf("bad auth header: %q", auth)
	}
}

func TestResolve_Denials(t *testing.T) {
	// Route-level denials carry {reason}; chain-level rejections carry {code}.
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
		{"no_address", 403, `{"reason":"SSHGW_ROUTE_NO_ADDRESS"}`, "SSHGW_ROUTE_NO_ADDRESS", ""},
		{"token_invalid", 401, `{"code":"AUTH_TOKEN_INVALID"}`, "", "AUTH_TOKEN_INVALID"},
		{"access_denied", 403, `{"code":"ACCESS_DENIED"}`, "", "ACCESS_DENIED"},
		{"rate_limited", 429, `{"code":"RATE_LIMITED"}`, "", "RATE_LIMITED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, tc.status, tc.body, nil, nil)
			defer srv.Close()

			r, err := mustClient(t, srv.URL).Resolve(context.Background(), "slug", "203.0.113.7")
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

	_, err := mustClient(t, srv.URL).Resolve(context.Background(), "slug", "203.0.113.7")
	if err == nil {
		t.Fatal("expected error on 500")
	}
	var d *Denial
	if errors.As(err, &d) {
		t.Fatalf("500 must be a generic error, not a *Denial: %v", err)
	}
}

func TestResolve_Malformed200IsError(t *testing.T) {
	srv := newServer(t, 200, `{"ip":"","port":0,"user":""}`, nil, nil)
	defer srv.Close()

	if _, err := mustClient(t, srv.URL).Resolve(context.Background(), "slug", "203.0.113.7"); err == nil {
		t.Fatal("expected error on empty 200 body")
	}
}

func TestResolve_TransportErrorFailsClosed(t *testing.T) {
	// Nothing listening: the client must return an error, never a route.
	c := mustClient(t, "http://127.0.0.1:1") // unroutable/refused
	if _, err := c.Resolve(context.Background(), "slug", "203.0.113.7"); err == nil {
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
