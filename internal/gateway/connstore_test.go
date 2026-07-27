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
	want := &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu"}
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

func TestConnStore_SessionCandidatesAccumulate(t *testing.T) {
	s := newConnStore(time.Minute)
	if _, _, ok := s.getSessionAttr("c1"); ok {
		t.Fatal("empty store must miss")
	}
	// Candidates accumulate (set semantics); a duplicate add is idempotent.
	s.addSessionCandidate("c1", "SHA256:aaa")
	s.addSessionCandidate("c1", "SHA256:bbb")
	s.addSessionCandidate("c1", "SHA256:aaa")
	fps, am, ok := s.getSessionAttr("c1")
	if !ok || am != "publickey" {
		t.Fatalf("attr: am=%q ok=%v", am, ok)
	}
	// Returned sorted and de-duplicated.
	if len(fps) != 2 || fps[0] != "SHA256:aaa" || fps[1] != "SHA256:bbb" {
		t.Fatalf("candidate set: %+v", fps)
	}
}

func TestConnStore_SessionPasswordLastWriteWins(t *testing.T) {
	s := newConnStore(time.Minute)
	// A publickey candidate followed by a password fallback: method flips to
	// password (the audit reports password; candidates are suppressed upstream).
	s.addSessionCandidate("c1", "SHA256:aaa")
	s.setSessionPassword("c1")
	_, am, ok := s.getSessionAttr("c1")
	if !ok || am != "password" {
		t.Fatalf("expected password method last-write-wins, got am=%q ok=%v", am, ok)
	}
}

func TestConnStoreExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newConnStore(2 * time.Minute)
	s.now = func() time.Time { return now }

	s.memoPut("c1", "fp1", memoEntry{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "ubuntu"}})
	s.putHostKeys("c1", []string{"ssh-ed25519 AAAA"})
	s.addSessionCandidate("c1", "SHA256:abc")

	// Still inside the TTL window.
	now = now.Add(time.Minute)
	if _, ok := s.memoGet("c1", "fp1"); !ok {
		t.Error("memo should be live within TTL")
	}
	if _, ok := s.getHostKeys("c1"); !ok {
		t.Error("host keys should be live within TTL")
	}
	if _, _, ok := s.getSessionAttr("c1"); !ok {
		t.Error("session attr should be live within TTL")
	}

	// Past the TTL: all expire.
	now = now.Add(2 * time.Minute)
	if _, ok := s.memoGet("c1", "fp1"); ok {
		t.Error("memo should expire after TTL")
	}
	if _, ok := s.getHostKeys("c1"); ok {
		t.Error("host keys should expire after TTL")
	}
	if _, _, ok := s.getSessionAttr("c1"); ok {
		t.Error("session attr should expire after TTL")
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
