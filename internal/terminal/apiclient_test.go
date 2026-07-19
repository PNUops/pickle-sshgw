package terminal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedeem_AllowAndAuthHeader(t *testing.T) {
	api := startFakeAPI(t)
	api.redeemResult = RedeemResult{
		SessionID: "s1", UserID: 42, VMID: 55, VMIp: "172.29.0.17", Port: 22,
		User: "student", HostKeys: []string{"ssh-ed25519 AAAA"},
	}
	c := NewAPIClient(api.baseURL(), "tok", 0)
	res, err := c.Redeem(context.Background(), "ticket-value")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if res.SessionID != "s1" || res.VMIp != "172.29.0.17" || res.User != "student" || len(res.HostKeys) != 1 {
		t.Fatalf("bad result: %+v", res)
	}
	if api.gotAuth != "Bearer tok" {
		t.Fatalf("bad auth: %q", api.gotAuth)
	}
}

func TestRedeem_DenyReasons(t *testing.T) {
	for _, reason := range []string{reasonTicketInvalid, reasonVMNotRunning, reasonAccessRevoked, reasonTerminalDisabled} {
		t.Run(reason, func(t *testing.T) {
			api := startFakeAPI(t)
			api.redeemReason = reason
			c := NewAPIClient(api.baseURL(), "tok", 0)
			_, err := c.Redeem(context.Background(), "x")
			var d *Denial
			if !errors.As(err, &d) || d.Reason != reason {
				t.Fatalf("want Denial %q, got %v", reason, err)
			}
		})
	}
}

func TestRedeem_EmptyHostKeysFailsClosed(t *testing.T) {
	api := startFakeAPI(t)
	api.redeemResult = RedeemResult{SessionID: "s", VMIp: "1.2.3.4", Port: 22, User: "student"} // no hostKeys
	c := NewAPIClient(api.baseURL(), "tok", 0)
	_, err := c.Redeem(context.Background(), "x")
	if err == nil {
		t.Fatal("expected fail-closed on empty hostKeys")
	}
	var d *Denial
	if errors.As(err, &d) {
		t.Fatalf("empty hostKeys must be a generic error, not a Denial: %v", err)
	}
	// Must be distinguishable so the WS layer can map it to 4006 (host-key), not 1001.
	if !errors.Is(err, ErrNoHostKeys) {
		t.Fatalf("empty hostKeys must wrap ErrNoHostKeys: %v", err)
	}
}

func TestRedeem_UnexpectedStatusIsError(t *testing.T) {
	api := startFakeAPI(t)
	api.redeemStatusOverride = http.StatusInternalServerError
	c := NewAPIClient(api.baseURL(), "tok", 0)
	if _, err := c.Redeem(context.Background(), "x"); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestRedeem_TransportErrorFailsClosed(t *testing.T) {
	c := NewAPIClient("http://127.0.0.1:1", "tok", 0)
	if _, err := c.Redeem(context.Background(), "x"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestSessionStart_ConflictAndOK(t *testing.T) {
	api := startFakeAPI(t)
	c := NewAPIClient(api.baseURL(), "tok", 0)
	if err := c.SessionStart(context.Background(), "s1", "203.0.113.7"); err != nil {
		t.Fatalf("SessionStart 204: %v", err)
	}
	if len(api.sessionStarts) != 1 || api.sessionStarts[0].ClientIP != "203.0.113.7" {
		t.Fatalf("session-start not captured: %+v", api.sessionStarts)
	}
	api.sessionStartStatus = http.StatusConflict
	if err := c.SessionStart(context.Background(), "s1", "x"); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("want ErrSessionConflict, got %v", err)
	}
}

func TestSessionEnd_Idempotent2xx(t *testing.T) {
	api := startFakeAPI(t)
	c := NewAPIClient(api.baseURL(), "tok", 0)
	req := SessionEndRequest{SessionID: "s1", Reason: EndClientClosed, DurationSeconds: 5, BytesIn: 10, BytesOut: 20}
	if err := c.SessionEnd(context.Background(), req); err != nil {
		t.Fatalf("SessionEnd: %v", err)
	}
	if api.endCount() != 1 || api.sessionEnds[0].Reason != EndClientClosed || api.sessionEnds[0].BytesOut != 20 {
		t.Fatalf("session-end not captured: %+v", api.sessionEnds)
	}
}

func TestRevalidate_AllowDenyError(t *testing.T) {
	api := startFakeAPI(t)
	c := NewAPIClient(api.baseURL(), "tok", 0)

	// allow
	api.revalidateFn = func(int64) (bool, string) { return true, "" }
	if err := c.Revalidate(context.Background(), "s1"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	// deny
	api.revalidateFn = func(int64) (bool, string) { return false, reasonAccessRevoked }
	err := c.Revalidate(context.Background(), "s1")
	var d *Denial
	if !errors.As(err, &d) || d.Reason != reasonAccessRevoked {
		t.Fatalf("want Denial ACCESS_REVOKED, got %v", err)
	}
}

func TestRevalidate_TransportErrorIsGeneric(t *testing.T) {
	c := NewAPIClient("http://127.0.0.1:1", "tok", 0)
	err := c.Revalidate(context.Background(), "s1")
	if err == nil {
		t.Fatal("expected transport error")
	}
	var d *Denial
	if errors.As(err, &d) {
		t.Fatalf("transport error must not be a Denial (fail-open path): %v", err)
	}
}

// The redeem request must carry the ticket in the body (by ticket only — no
// user/VM enumeration fields).
func TestRedeem_RequestShape(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		body = string(b)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason":"TICKET_INVALID"}`))
	}))
	defer srv.Close()
	c := NewAPIClient(srv.URL, "tok", 0)
	_, _ = c.Redeem(context.Background(), "the-ticket")
	if !strings.Contains(body, `"ticket":"the-ticket"`) {
		t.Fatalf("redeem body missing ticket: %q", body)
	}
}
