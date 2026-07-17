package gateway

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// LoadUpstreamKey reads and validates the platform upstream private key used to
// authenticate the gateway→VM hop on the publickey path. It returns the raw PEM
// bytes (which sshpiperd parses again when it builds the upstream auth) but only
// after parsing them here, so a missing or malformed key file is caught at
// startup and the plugin refuses to run — the same fail-closed posture as a
// missing bearer token. The private key is never logged.
func LoadUpstreamKey(path string) ([]byte, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gateway: read upstream key %q: %w", path, err)
	}
	if _, err := ssh.ParsePrivateKey(pem); err != nil {
		return nil, fmt.Errorf("gateway: upstream key %q is not a valid private key: %w", path, err)
	}
	return pem, nil
}
