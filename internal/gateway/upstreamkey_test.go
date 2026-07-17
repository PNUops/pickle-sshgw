package gateway

import (
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeKeyFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadUpstreamKey_Valid(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "pickle-platform-upstream")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(blk)
	path := writeKeyFile(t, t.TempDir(), "key", pemBytes)

	got, err := LoadUpstreamKey(path)
	if err != nil {
		t.Fatalf("LoadUpstreamKey: %v", err)
	}
	if string(got) != string(pemBytes) {
		t.Error("LoadUpstreamKey must return the raw PEM unchanged")
	}
	// Sanity: the returned bytes parse as the same key sshpiperd will use.
	if _, err := ssh.ParsePrivateKey(got); err != nil {
		t.Errorf("returned bytes not parseable: %v", err)
	}
}

func TestLoadUpstreamKey_Missing(t *testing.T) {
	if _, err := LoadUpstreamKey(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing key file (fail-closed startup)")
	}
}

func TestLoadUpstreamKey_Garbage(t *testing.T) {
	path := writeKeyFile(t, t.TempDir(), "garbage", []byte("this is not a private key\n"))
	if _, err := LoadUpstreamKey(path); err == nil {
		t.Fatal("expected error for a non-key file (fail-closed startup)")
	}
}
