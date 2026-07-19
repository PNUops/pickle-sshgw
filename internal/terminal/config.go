// Package terminal implements sshgw-terminal-bridge: the low-privilege Go daemon
// on the sshgw LXC (172.30.1.30) that terminates the browser WebSocket for the
// Pickle web terminal (console xterm.js) and pipes it to the user's VM over SSH.
//
// It holds no DB, no Proxmox token and no credential-cipher key. It is an
// enforcer in the control/data-plane split (docs/plan/05-ssh-access.md Path B,
// docs/api/internal.md Link 3): pickle-api mints one-time tickets and answers the
// bridge's internal control calls (redeem / session lifecycle / revalidate) while
// the bridge owns the real WS+SSH sessions and reports them back for the admin
// mirror. pickle-api never touches terminal bytes.
//
// The package is fail-closed throughout: a missing token or terminal key aborts
// startup, an unverifiable host key refuses the SSH hop, and any redeem/authz
// denial closes the WebSocket with a mapped close code.
package terminal

import (
	"fmt"
	"strings"
	"time"
)

// Defaults for the tunables. Idle/ping/revalidate are overridable (env or, in
// tests, direct Config fields) so the timing-sensitive behaviours can be exercised
// quickly.
const (
	DefaultWSListen            = "172.30.1.30:8082"
	DefaultControlListen       = "172.30.1.30:8083"
	DefaultAPIBase             = "http://172.30.1.20:8080"
	DefaultConsoleOrigin       = "https://pickle.pnuops.com"
	DefaultTerminalKeyFile     = "/etc/pickle/sshgw/terminal_ed25519_key"
	DefaultWSAllowedSourceIP   = "172.30.1.10" // LXC 100 nginx TLS tier
	DefaultControlSourceIP     = "172.30.1.20" // LXC 101 pickle-api
	DefaultIdleTimeout         = 15 * time.Minute
	DefaultPingInterval        = 30 * time.Second
	DefaultRevalidateInterval  = 60 * time.Second
	DefaultSSHConnectTimeout   = 10 * time.Second
	DefaultWSWriteTimeout      = 10 * time.Second
	DefaultAPITimeout          = 5 * time.Second
	DefaultControlExitFrameWin = 3 * time.Second
	// DefaultRevalidateMaxFailures bounds the fail-open window: after this many
	// *consecutive* revalidation-poll transport errors the session is closed
	// (1001) rather than kept alive indefinitely — otherwise a long api outage
	// would leave sessions immune to kill-switch/membership-revocation/admin
	// force-terminate (all of which flow through api). At the 60s default poll
	// this is ~5 minutes.
	DefaultRevalidateMaxFailures = 5
)

// Config holds the bridge configuration, sourced from the environment by the
// caller (see cmd/sshgw-terminal-bridge). GatewayToken, ControlToken,
// ConsoleOrigin and TerminalKeyFile are mandatory — an empty value is a
// configuration error so the daemon fails closed rather than serving without a
// trust anchor.
type Config struct {
	// WSListen is the browser-WS ingress address (proxied from the LXC 100 TLS
	// tier). Source IP is additionally checked against WSAllowedSourceIP.
	WSListen string
	// ControlListen is the api→bridge control address (force-terminate).
	ControlListen string
	// APIBase is the pickle-api base, e.g. "http://172.30.1.20:8080".
	APIBase string
	// GatewayToken is the shared bearer PICKLE_SSHGW_TOKEN used on the bridge→api
	// internal calls (same token/chain as Link 1).
	GatewayToken string
	// ControlToken is PICKLE_TERMINAL_CONTROL_TOKEN, verified on inbound control
	// requests (distinct token, independent revocation).
	ControlToken string
	// ConsoleOrigin is the exact Origin the browser WS handshake must present.
	ConsoleOrigin string
	// TerminalKeyFile is the platform terminal ed25519 private key path.
	TerminalKeyFile string
	// WSAllowedSourceIP is the only TCP peer allowed to reach the WS ingress
	// (nginx on LXC 100). nftables enforces this too; the code checks in depth.
	WSAllowedSourceIP string
	// ControlAllowedSourceIP is the only TCP peer allowed to reach the control
	// port (pickle-api on LXC 101).
	ControlAllowedSourceIP string
	// IdleTimeout closes a session after this long with no client *input*
	// (resize/ping do not reset it). Zero uses DefaultIdleTimeout.
	IdleTimeout time.Duration
	// PingInterval is the server WS ping cadence (keeps CF from idling ~100s).
	PingInterval time.Duration
	// RevalidateInterval is the bridge→api revalidation poll cadence.
	RevalidateInterval time.Duration
	// RevalidateMaxFailures caps consecutive revalidation-poll transport errors
	// before the session is closed (fail-open is bounded, not indefinite). Zero
	// uses DefaultRevalidateMaxFailures. An explicit deny always closes at once.
	RevalidateMaxFailures int
	// SSHConnectTimeout bounds the dial+handshake to the VM.
	SSHConnectTimeout time.Duration
	// WSWriteTimeout bounds a single WS write; exceeding it (slow client) closes
	// the session 4006.
	WSWriteTimeout time.Duration
	// APITimeout bounds a single bridge→api internal call.
	APITimeout time.Duration
}

// Validate enforces the fail-closed preconditions and normalises zero tunables to
// their defaults.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.APIBase) == "" {
		return fmt.Errorf("terminal: APIBase is required")
	}
	if strings.TrimSpace(c.GatewayToken) == "" {
		return fmt.Errorf("terminal: gateway bearer token is required (PICKLE_SSHGW_TOKEN unset)")
	}
	if strings.TrimSpace(c.ControlToken) == "" {
		return fmt.Errorf("terminal: control token is required (PICKLE_TERMINAL_CONTROL_TOKEN unset)")
	}
	if strings.TrimSpace(c.ConsoleOrigin) == "" {
		return fmt.Errorf("terminal: console origin is required")
	}
	if strings.TrimSpace(c.TerminalKeyFile) == "" {
		return fmt.Errorf("terminal: terminal key file path is required")
	}
	if strings.TrimSpace(c.WSAllowedSourceIP) == "" {
		return fmt.Errorf("terminal: WS allowed source IP is required (fail-closed)")
	}
	if strings.TrimSpace(c.ControlAllowedSourceIP) == "" {
		return fmt.Errorf("terminal: control allowed source IP is required (fail-closed)")
	}
	c.applyDefaults()
	return nil
}

func (c *Config) applyDefaults() {
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.PingInterval <= 0 {
		c.PingInterval = DefaultPingInterval
	}
	if c.RevalidateInterval <= 0 {
		c.RevalidateInterval = DefaultRevalidateInterval
	}
	if c.RevalidateMaxFailures <= 0 {
		c.RevalidateMaxFailures = DefaultRevalidateMaxFailures
	}
	if c.SSHConnectTimeout <= 0 {
		c.SSHConnectTimeout = DefaultSSHConnectTimeout
	}
	if c.WSWriteTimeout <= 0 {
		c.WSWriteTimeout = DefaultWSWriteTimeout
	}
	if c.APITimeout <= 0 {
		c.APITimeout = DefaultAPITimeout
	}
}
