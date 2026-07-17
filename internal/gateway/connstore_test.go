package gateway

import (
	"testing"
	"time"

	"github.com/pickle/sshgw/internal/route"
)

func TestConnStore_MemoRoundTrip(t *testing.T) {
	s := newConnStore(time.Minute)
	if _, ok := s.memoGet("c1", "fp1"); ok {
		t.Fatal("empty store must miss")
	}
	want := &route.Route{IP: "172.29.4.11", Port: 22, User: "student"}
	s.memoPut("c1", "fp1", memoEntry{route: want})
	got, ok := s.memoGet("c1", "fp1")
	if !ok || got.route != want {
		t.Fatalf("memo round trip: got %+v ok=%v", got, ok)
	}
	// Different fingerprint on the same connection is a distinct entry.
	if _, ok := s.memoGet("c1", "fp2"); ok {
		t.Fatal("distinct fingerprint must miss")
	}
}

func TestConnStore_HostKeysRoundTrip(t *testing.T) {
	s := newConnStore(time.Minute)
	if _, ok := s.getHostKeys("c1"); ok {
		t.Fatal("empty store must miss")
	}
	s.putHostKeys("c1", []string{"ssh-ed25519 AAAA"})
	got, ok := s.getHostKeys("c1")
	if !ok || len(got) != 1 || got[0] != "ssh-ed25519 AAAA" {
		t.Fatalf("host keys round trip: got %+v ok=%v", got, ok)
	}
}

func TestConnStoreExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newConnStore(2 * time.Minute)
	s.now = func() time.Time { return now }

	s.memoPut("c1", "fp1", memoEntry{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "student"}})
	s.putHostKeys("c1", []string{"ssh-ed25519 AAAA"})

	// Still inside the TTL window.
	now = now.Add(time.Minute)
	if _, ok := s.memoGet("c1", "fp1"); !ok {
		t.Error("memo should be live within TTL")
	}
	if _, ok := s.getHostKeys("c1"); !ok {
		t.Error("host keys should be live within TTL")
	}

	// Past the TTL: both expire.
	now = now.Add(2 * time.Minute)
	if _, ok := s.memoGet("c1", "fp1"); ok {
		t.Error("memo should expire after TTL")
	}
	if _, ok := s.getHostKeys("c1"); ok {
		t.Error("host keys should expire after TTL")
	}
}

// A write after expiry must not leave stale entries from other connections
// behind — the lazy sweep on write reclaims them.
func TestConnStore_SweepOnWrite(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newConnStore(time.Minute)
	s.now = func() time.Time { return now }

	s.memoPut("old", "fp", memoEntry{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "s"}})
	s.putHostKeys("old", []string{"k"})

	now = now.Add(2 * time.Minute) // everything from "old" is now expired
	s.memoPut("new", "fp", memoEntry{route: &route.Route{IP: "5.6.7.8", Port: 22, User: "s"}})

	if _, present := s.memo[memoKey("old", "fp")]; present {
		t.Error("expired memo entry should have been swept on write")
	}
	if _, present := s.host["old"]; present {
		t.Error("expired host entry should have been swept on write")
	}
}
