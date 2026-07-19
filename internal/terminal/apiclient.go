package terminal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// APIClient calls Link 3a of the internal infra API (docs/api/internal.md):
// bridge → pickle-api under /internal/terminal/. Same server-side chain as Link 1
// (Bearer PICKLE_SSHGW_TOKEN, source 172.30.1.30). Every call is fail-closed: a
// transport error or unexpected status is surfaced to the caller, never silently
// treated as success.
type APIClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewAPIClient builds the client. baseURL and token are required (the caller has
// already validated them via Config.Validate).
func NewAPIClient(baseURL, token string, timeout time.Duration) *APIClient {
	if timeout <= 0 {
		timeout = DefaultAPITimeout
	}
	return &APIClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: timeout},
	}
}

// RedeemResult is the allow-path body of POST /internal/terminal/redeem.
type RedeemResult struct {
	SessionID string   `json:"sessionId"`
	UserID    int64    `json:"userId"`
	VMID      int64    `json:"vmId"`
	VMIp      string   `json:"vmIp"`
	Port      int      `json:"port"`
	User      string   `json:"user"`
	HostKeys  []string `json:"hostKeys"`
}

// Denial is a structured redeem/revalidate deny (403 {reason} for redeem, or a
// revalidate 200 with allow=false and a reason). Reason carries the Link 3 codes.
type Denial struct {
	Reason string
}

func (d *Denial) Error() string { return "terminal: denied: " + d.Reason }

// Redeem calls POST /internal/terminal/redeem with the one-time ticket. On allow
// it returns *RedeemResult. On a 403 deny it returns a *Denial (Reason set). Any
// other outcome (transport, unexpected status, unparseable/incomplete body) is a
// generic error the caller treats as fail-closed.
func (c *APIClient) Redeem(ctx context.Context, ticket string) (*RedeemResult, error) {
	raw, status, err := c.post(ctx, "/internal/terminal/redeem", map[string]string{"ticket": ticket})
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
		var r RedeemResult
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("terminal: decode redeem 200: %w", err)
		}
		if r.SessionID == "" || r.VMIp == "" || r.Port <= 0 || r.User == "" {
			return nil, fmt.Errorf("terminal: redeem 200 missing sessionId/vmIp/port/user: %q", string(raw))
		}
		if len(r.HostKeys) == 0 {
			// Distinguishable from other redeem failures: an absent host-key set
			// is a host-key (connection) problem — the caller maps it to WS 4006,
			// not the generic maintenance close.
			return nil, fmt.Errorf("terminal: redeem 200 has no hostKeys (fail-closed): %q: %w", string(raw), ErrNoHostKeys)
		}
		return &r, nil
	case http.StatusForbidden:
		var d struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &d)
		if d.Reason == "" {
			return nil, fmt.Errorf("terminal: redeem 403 with no reason: %q", string(raw))
		}
		return nil, &Denial{Reason: d.Reason}
	default:
		return nil, fmt.Errorf("terminal: redeem unexpected status %d: %q", status, string(raw))
	}
}

// SessionStart calls POST /internal/terminal/session-start. It returns nil on 204.
// A 409 (never-redeemed / already-ended — inconsistent) returns ErrSessionConflict
// so the caller closes the WS. Any other outcome is a generic error.
func (c *APIClient) SessionStart(ctx context.Context, sessionID, clientIP string) error {
	raw, status, err := c.post(ctx, "/internal/terminal/session-start",
		map[string]string{"sessionId": sessionID, "clientIp": clientIP})
	if err != nil {
		return err
	}
	switch status {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusConflict:
		return ErrSessionConflict
	default:
		return fmt.Errorf("terminal: session-start unexpected status %d: %q", status, string(raw))
	}
}

// ErrSessionConflict is returned by SessionStart on a 409.
var ErrSessionConflict = fmt.Errorf("terminal: session-start conflict (409)")

// ErrNoHostKeys wraps a redeem-200 response whose hostKeys array is empty — a
// host-key/connection failure the WS layer maps to close 4006 (not 1001).
var ErrNoHostKeys = fmt.Errorf("terminal: redeem returned no host keys")

// SessionEndRequest is the body of POST /internal/terminal/session-end. Byte
// values are counts only — never content (M5).
type SessionEndRequest struct {
	SessionID       string `json:"sessionId"`
	Reason          string `json:"reason"`
	DurationSeconds int64  `json:"durationSeconds"`
	BytesIn         int64  `json:"bytesIn"`
	BytesOut        int64  `json:"bytesOut"`
}

// Session-end reason values (docs/api/internal.md Link 3).
const (
	EndClientClosed       = "CLIENT_CLOSED"
	EndIdleTimeout        = "IDLE_TIMEOUT"
	EndForceTerminated    = "FORCE_TERMINATED"
	EndRevalidationDenied = "REVALIDATION_DENIED"
	EndSSHFailed          = "SSH_FAILED"
	EndBridgeShutdown     = "BRIDGE_SHUTDOWN"
)

// SessionEnd calls POST /internal/terminal/session-end. The endpoint is idempotent
// (a repeated/unknown sessionId is a 204 no-op), so this is retry-safe. Returns
// nil on 2xx, a generic error otherwise (the caller logs but the session is
// already torn down).
func (c *APIClient) SessionEnd(ctx context.Context, req SessionEndRequest) error {
	raw, status, err := c.post(ctx, "/internal/terminal/session-end", req)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("terminal: session-end unexpected status %d: %q", status, string(raw))
	}
	return nil
}

// Revalidate calls POST /internal/terminal/revalidate. It returns (nil) when the
// session is still allowed, a *Denial (Reason set) when the api denies, or a
// generic error on transport/decoding failure (the caller treats a transport
// failure as fail-open — a single missed poll must not kill a live session — but
// an explicit deny as fail-closed).
func (c *APIClient) Revalidate(ctx context.Context, sessionID string) error {
	raw, status, err := c.post(ctx, "/internal/terminal/revalidate", map[string]string{"sessionId": sessionID})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("terminal: revalidate unexpected status %d: %q", status, string(raw))
	}
	var body struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("terminal: decode revalidate body: %w", err)
	}
	if body.Allow {
		return nil
	}
	if body.Reason == "" {
		return fmt.Errorf("terminal: revalidate deny with no reason: %q", string(raw))
	}
	return &Denial{Reason: body.Reason}
}

// post marshals body, POSTs it with the bearer header, and returns the (limited)
// response bytes and status. A transport error or marshal failure is returned as
// a generic error.
func (c *APIClient) post(ctx context.Context, path string, body any) ([]byte, int, error) {
	enc, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("terminal: marshal %s request: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(enc))
	if err != nil {
		return nil, 0, fmt.Errorf("terminal: build %s request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("terminal: %s request failed: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, 0, fmt.Errorf("terminal: read %s response: %w", path, err)
	}
	return raw, resp.StatusCode, nil
}
