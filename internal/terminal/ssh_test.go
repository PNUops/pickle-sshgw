package terminal

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDialVM_HostKeyPinMatch(t *testing.T) {
	vm := startFakeVM(t, fakeVMOpts{})
	client, err := DialVM(context.Background(), DialParams{
		Addr: vm.addr, User: "ubuntu",
		HostKeys: []string{vm.hostKeyLine},
		Signer:   newTestSigner(t), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialVM: %v", err)
	}
	defer client.Close()
	// A session channel must open (single shell+pty channel path).
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	_ = sess.Close()
}

func TestDialVM_HostKeyMismatchFailsClosed(t *testing.T) {
	vm := startFakeVM(t, fakeVMOpts{})
	other := startFakeVM(t, fakeVMOpts{}) // its host key line does not match vm
	_, err := DialVM(context.Background(), DialParams{
		Addr: vm.addr, User: "ubuntu",
		HostKeys: []string{other.hostKeyLine},
		Signer:   newTestSigner(t), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected host-key mismatch failure")
	}
	if !strings.Contains(err.Error(), "handshake") && !strings.Contains(err.Error(), "mismatch") {
		t.Logf("mismatch surfaced as: %v", err)
	}
}

func TestDialVM_EmptyHostKeysFailsClosed(t *testing.T) {
	vm := startFakeVM(t, fakeVMOpts{})
	_, err := DialVM(context.Background(), DialParams{
		Addr: vm.addr, User: "ubuntu",
		HostKeys: nil,
		Signer:   newTestSigner(t), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected fail-closed on empty host key set")
	}
}

func TestDialVM_AllMalformedHostKeysFailClosed(t *testing.T) {
	vm := startFakeVM(t, fakeVMOpts{})
	_, err := DialVM(context.Background(), DialParams{
		Addr: vm.addr, User: "ubuntu",
		HostKeys: []string{"not-a-key", "also garbage"},
		Signer:   newTestSigner(t), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected fail-closed when no host key parses")
	}
}

// A pinned set with one good line and one garbage line still verifies against
// the good line (garbage is skipped, not trusted).
func TestDialVM_MixedHostKeysUsesValidLine(t *testing.T) {
	vm := startFakeVM(t, fakeVMOpts{})
	client, err := DialVM(context.Background(), DialParams{
		Addr: vm.addr, User: "ubuntu",
		HostKeys: []string{"garbage-line", vm.hostKeyLine},
		Signer:   newTestSigner(t), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialVM with mixed keys: %v", err)
	}
	_ = client.Close()
}
