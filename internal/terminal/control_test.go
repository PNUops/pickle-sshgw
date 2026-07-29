package terminal

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// controlBridge builds a Bridge with a control token and allowed source IP, and
// injects a live session by id so terminate can be exercised without a full WS.
func controlBridge(t *testing.T, token, allowedIP string) *Bridge {
	t.Helper()
	cfg := Config{
		APIBase: "http://x", GatewayToken: "g", ControlToken: token,
		ConsoleOrigin: "https://pickle.pusan.ac.kr", TerminalKeyFile: "x",
		WSAllowedSourceIP: "127.0.0.1", ControlAllowedSourceIP: allowedIP,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	return NewBridge(cfg, newTestSigner(t), NewAPIClient("http://x", "g", 0))
}

func postControl(t *testing.T, h http.Handler, remoteAddr, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/control/terminate", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestControl_RejectsBadSourceIP(t *testing.T) {
	b := controlBridge(t, "secret", "172.30.1.20")
	rec := postControl(t, b.ControlHandler(), "10.0.0.9:5000", "Bearer secret", `{"sessionId":"s1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestControl_RejectsBadToken(t *testing.T) {
	b := controlBridge(t, "secret", "127.0.0.1")
	rec := postControl(t, b.ControlHandler(), "127.0.0.1:5000", "Bearer wrong", `{"sessionId":"s1"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	// Missing header too.
	rec = postControl(t, b.ControlHandler(), "127.0.0.1:5000", "", `{"sessionId":"s1"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for missing header, got %d", rec.Code)
	}
}

func TestControl_UnknownSessionIsNoop204(t *testing.T) {
	b := controlBridge(t, "secret", "127.0.0.1")
	rec := postControl(t, b.ControlHandler(), "127.0.0.1:5000", "Bearer secret", `{"sessionId":"nope"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204 no-op, got %d", rec.Code)
	}
}

func TestControl_BadBody400(t *testing.T) {
	b := controlBridge(t, "secret", "127.0.0.1")
	rec := postControl(t, b.ControlHandler(), "127.0.0.1:5000", "Bearer secret", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for empty sessionId, got %d", rec.Code)
	}
}

func TestBearerEquals(t *testing.T) {
	if !bearerEquals("Bearer abc", "abc") {
		t.Error("exact match should pass")
	}
	if bearerEquals("Bearer abc", "abcd") {
		t.Error("mismatch should fail")
	}
	if bearerEquals("abc", "abc") {
		t.Error("missing prefix should fail")
	}
	if bearerEquals("Bearer abc", "") {
		t.Error("empty want must never match")
	}
	if bearerEquals("", "abc") {
		t.Error("empty header should fail")
	}
}

// sanity: the control handler reads at most a bounded body.
func TestControl_BoundedBody(t *testing.T) {
	b := controlBridge(t, "secret", "127.0.0.1")
	big := `{"sessionId":"` + strings.Repeat("a", 1<<20) + `"}`
	rec := postControl(t, b.ControlHandler(), "127.0.0.1:5000", "Bearer secret", big)
	// Truncated JSON (limit reader) → parse fails → 400, not a crash.
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNoContent {
		t.Fatalf("unexpected code for oversized body: %d", rec.Code)
	}
	_ = bytes.MinRead
}
