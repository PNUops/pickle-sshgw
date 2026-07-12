// Package route is the client for Link 1 of the internal infra API
// (docs/api/internal.md): sshgw → pickle-api POST /internal/sshgw/route.
// It resolves an SSH slug to the upstream VM the session should be piped to,
// or reports why the route was denied. It is deliberately fail-closed: any
// transport error, unexpected status, or unparseable body yields an error and
// never a usable route.
package route

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

// Config holds the client configuration, sourced from the environment by the
// caller. Token is mandatory — an empty token is a configuration error (the
// gateway must fail closed rather than call the API unauthenticated).
type Config struct {
	// BaseURL is the pickle-api base, e.g. "http://172.30.1.20:8080".
	BaseURL string
	// Token is the shared bearer PICKLE_SSHGW_TOKEN.
	Token string
	// Timeout bounds a single route lookup. Zero uses DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout bounds a route lookup so a stalled API cannot hang an SSH
// handshake indefinitely.
const DefaultTimeout = 5 * time.Second

// Validate enforces the fail-closed precondition: a client cannot be built
// without a base URL and a token.
func (c Config) Validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return fmt.Errorf("route: BaseURL is required")
	}
	if strings.TrimSpace(c.Token) == "" {
		return fmt.Errorf("route: bearer token is required (PICKLE_SSHGW_TOKEN unset)")
	}
	return nil
}

// Client calls the route-resolution endpoint.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a Client, returning an error if the config is not fail-closed safe.
func New(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	to := cfg.Timeout
	if to <= 0 {
		to = DefaultTimeout
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: to},
	}, nil
}

// Route is the allowed upstream target (HTTP 200 response body).
type Route struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	User string `json:"user"`
}

// Denial is a structured, non-transport rejection. Reason carries the
// SSHGW_* route-level codes (403/404 bodies of shape {"reason": ...}); Code
// carries the chain-level problem+json codes (401/403/429 bodies of shape
// {"code": ...}). Exactly one is normally set. Denial implements error so the
// plugin can log the machine code while refusing the SSH auth.
type Denial struct {
	HTTPStatus int
	Reason     string // SSHGW_GATEWAY_DISABLED, SSHGW_ROUTE_NOT_FOUND, ...
	Code       string // AUTH_TOKEN_INVALID, ACCESS_DENIED, RATE_LIMITED
}

func (d *Denial) Error() string {
	switch {
	case d.Reason != "":
		return fmt.Sprintf("route denied (%d): %s", d.HTTPStatus, d.Reason)
	case d.Code != "":
		return fmt.Sprintf("route rejected (%d): %s", d.HTTPStatus, d.Code)
	default:
		return fmt.Sprintf("route denied (%d): unspecified", d.HTTPStatus)
	}
}

// Machine returns the single machine-readable token for this denial (Reason if
// present, else Code), for logging/audit.
func (d *Denial) Machine() string {
	if d.Reason != "" {
		return d.Reason
	}
	return d.Code
}

type routeRequest struct {
	Slug     string `json:"slug"`
	SourceIP string `json:"sourceIp"`
}

// denialBody carries both possible discriminators; whichever the server sends
// is populated.
type denialBody struct {
	Reason string `json:"reason"`
	Code   string `json:"code"`
}

// Resolve calls POST /internal/sshgw/route. slug is the SSH username the client
// supplied; sourceIP is the real client IP recovered from the PROXY header. On
// success it returns *Route. A route/auth rejection returns a *Denial. Any
// other failure (transport, bad status, unparseable body) returns a generic
// error. Callers treat every non-nil error as "refuse the session".
func (c *Client) Resolve(ctx context.Context, slug, sourceIP string) (*Route, error) {
	body, err := json.Marshal(routeRequest{Slug: slug, SourceIP: sourceIP})
	if err != nil {
		return nil, fmt.Errorf("route: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.BaseURL+"/internal/sshgw/route", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("route: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("route: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("route: read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var r Route
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("route: decode 200 body: %w", err)
		}
		if r.IP == "" || r.Port <= 0 || r.User == "" {
			return nil, fmt.Errorf("route: 200 body missing ip/port/user: %q", string(raw))
		}
		return &r, nil

	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusTooManyRequests:
		var d denialBody
		_ = json.Unmarshal(raw, &d) // best effort; empty tokens still deny
		return nil, &Denial{
			HTTPStatus: resp.StatusCode,
			Reason:     d.Reason,
			Code:       d.Code,
		}

	default:
		return nil, fmt.Errorf("route: unexpected status %d: %q", resp.StatusCode, string(raw))
	}
}
