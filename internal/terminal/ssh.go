package terminal

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// Modern algorithm allowlists for the gateway→VM hop. curve25519 KEX only (with
// x/crypto's automatic strict-kex pseudo-algorithm, anti-Terrapin); AEAD/ETM
// ciphers and ETM MACs only; compression is never negotiated (Go's ssh has none).
var (
	allowedKEX = []string{
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
	}
	allowedCiphers = []string{
		"chacha20-poly1305@openssh.com",
		"aes256-gcm@openssh.com",
		"aes128-gcm@openssh.com",
	}
	allowedMACs = []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
	}
)

// LoadTerminalKey reads and validates the platform terminal private key used to
// authenticate the bridge→VM hop. It returns a signer, failing closed (aborting
// startup) if the file is missing or not a valid private key. The key is never
// logged.
func LoadTerminalKey(path string) (ssh.Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("terminal: read terminal key %q: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("terminal: terminal key %q is not a valid private key: %w", path, err)
	}
	return signer, nil
}

// DialParams are the inputs to DialVM, from the redeem response.
type DialParams struct {
	Addr     string // "ip:port"
	User     string
	HostKeys []string // authorized_keys-style lines; pinned type-agnostically
	Signer   ssh.Signer
	Timeout  time.Duration
}

// DialVM opens a locked-down SSH client to the VM. It pins the host key against
// the provided set (fail-closed on empty/mismatch), restricts KEX/cipher/MAC to
// the modern allowlists, uses a single publickey auth (the terminal key), and —
// because it builds the client with ssh.NewClient — rejects every
// server-initiated channel and discards every global request: the only channel
// ever opened is the one session the caller opens next (pty+shell). This blocks
// guest→infra reverse tunnels (direct/forwarded-tcpip, auth-agent, x11 are never
// requested and any incoming channel/global request is refused/discarded).
func DialVM(ctx context.Context, p DialParams) (*ssh.Client, error) {
	hostKeyCallback, err := pinnedHostKeyCallback(p.HostKeys)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(p.Signer)},
		HostKeyCallback: hostKeyCallback,
		// Banners are ignored silently (never logged — they are guest-controlled).
		BannerCallback: func(string) error { return nil },
		Config: ssh.Config{
			KeyExchanges: allowedKEX,
			Ciphers:      allowedCiphers,
			MACs:         allowedMACs,
		},
		Timeout: p.Timeout,
	}

	dialer := &net.Dialer{Timeout: p.Timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", p.Addr)
	if err != nil {
		return nil, fmt.Errorf("terminal: dial VM %s: %w", p.Addr, err)
	}
	// Enforce the connect/handshake deadline on the SSH handshake too.
	if p.Timeout > 0 {
		_ = netConn.SetDeadline(time.Now().Add(p.Timeout))
	}
	conn, chans, reqs, err := ssh.NewClientConn(netConn, p.Addr, cfg)
	if err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("terminal: SSH handshake to %s: %w", p.Addr, err)
	}
	// Clear the handshake deadline; the session runs without one (idle is
	// enforced at the WS layer).
	_ = netConn.SetDeadline(time.Time{})
	// ssh.NewClient starts the mux loop: it rejects any server-initiated channel
	// (we register no channel handlers) and discards incoming global requests.
	return ssh.NewClient(conn, chans, reqs), nil
}

// pinnedHostKeyCallback builds a type-agnostic exact-match host-key verifier from
// the authorized_keys-style lines. It is fail-closed: an empty set, or a set with
// no parseable entry, is an error (the bridge refuses to connect); at verify time
// a presented key that matches none of the pinned entries is rejected.
func pinnedHostKeyCallback(lines []string) (ssh.HostKeyCallback, error) {
	if len(lines) == 0 {
		return nil, fmt.Errorf("terminal: empty host key set (fail-closed)")
	}
	var pinned [][]byte
	for _, line := range lines {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			// A malformed pinned entry cannot match; skip rather than trust.
			continue
		}
		pinned = append(pinned, pk.Marshal())
	}
	if len(pinned) == 0 {
		return nil, fmt.Errorf("terminal: no parseable host keys (fail-closed)")
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		presented := key.Marshal()
		for _, p := range pinned {
			if bytes.Equal(p, presented) {
				return nil
			}
		}
		return fmt.Errorf("terminal: upstream host key mismatch (fail-closed)")
	}, nil
}
