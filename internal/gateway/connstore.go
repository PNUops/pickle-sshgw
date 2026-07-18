package gateway

import (
	"sync"
	"time"

	"github.com/pickle/sshgw/internal/route"
)

// defaultMemoTTL bounds how long a connection's memoized route results and
// pinned host keys live: just the SSH auth window. A client offers each key
// twice (probe, then signed) and may try several keys before falling back to
// password, all within a couple of minutes. Keeping the memo this short means
// revocation (key deletion / member removal) takes effect from the next
// connection — there is no cross-connection cache.
const defaultMemoTTL = 2 * time.Minute

// memoEntry is a memoized route-resolution outcome for one (connection,
// fingerprint) pair: exactly one of route/err is meaningful, mirroring what
// Resolve returned. Denials are memoized too, so a client re-offering the same
// key (probe then signed) costs a single API call.
type memoEntry struct {
	route *route.Route
	err   error
}

type memoRecord struct {
	entry   memoEntry
	expires time.Time
}

type hostRecord struct {
	keys    []string
	expires time.Time
}

// sessionRecord remembers, per connection, the credential that last succeeded in
// an auth callback — the one that authenticates the session. PipeStart reads it
// to attribute the sshgw.session audit to the fingerprint that actually
// authenticated (fingerprint empty on the password path).
type sessionRecord struct {
	fingerprint string
	authMethod  string
	expires     time.Time
}

// connStore memoizes per-(connection,fingerprint) route lookups and holds the
// per-connection pinned host keys the verify callback checks against. It is
// safe for concurrent use; entries expire after ttl and are swept lazily on
// write.
type connStore struct {
	ttl  time.Duration
	now  func() time.Time // injectable clock for tests
	mu   sync.Mutex
	memo map[string]memoRecord
	host map[string]hostRecord
	sess map[string]sessionRecord
}

func newConnStore(ttl time.Duration) *connStore {
	return &connStore{
		ttl:  ttl,
		now:  time.Now,
		memo: make(map[string]memoRecord),
		host: make(map[string]hostRecord),
		sess: make(map[string]sessionRecord),
	}
}

// memoKey joins the connection id and fingerprint. Both are opaque tokens
// without NUL bytes, so a NUL separator cannot be forged across the boundary.
func memoKey(connID, fingerprint string) string {
	return connID + "\x00" + fingerprint
}

// memoGet returns a memoized outcome for (connID, fingerprint) if present and
// unexpired.
func (s *connStore) memoGet(connID, fingerprint string) (memoEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.memo[memoKey(connID, fingerprint)]
	if !ok || !s.now().Before(rec.expires) {
		return memoEntry{}, false
	}
	return rec.entry, true
}

// memoPut records an outcome and opportunistically sweeps expired entries.
func (s *connStore) memoPut(connID, fingerprint string, e memoEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.memo[memoKey(connID, fingerprint)] = memoRecord{entry: e, expires: s.now().Add(s.ttl)}
}

// putHostKeys pins the host keys for a connection (set on a successful route so
// the later VerifyHostKeyCallback can check the upstream against them).
func (s *connStore) putHostKeys(connID string, keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.host[connID] = hostRecord{keys: keys, expires: s.now().Add(s.ttl)}
}

// getHostKeys returns the pinned host keys for a connection if present and
// unexpired.
func (s *connStore) getHostKeys(connID string) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.host[connID]
	if !ok || !s.now().Before(rec.expires) {
		return nil, false
	}
	return rec.keys, true
}

// putSessionAttr records the credential that just authenticated on a connection
// (overwriting: the last successful callback before PipeStart is the one that
// authenticates). fingerprint is empty on the password path.
func (s *connStore) putSessionAttr(connID, fingerprint, authMethod string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.sess[connID] = sessionRecord{fingerprint: fingerprint, authMethod: authMethod, expires: s.now().Add(s.ttl)}
}

// getSessionAttr returns the authenticating credential for a connection if
// present and unexpired.
func (s *connStore) getSessionAttr(connID string) (fingerprint, authMethod string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, present := s.sess[connID]
	if !present || !s.now().Before(rec.expires) {
		return "", "", false
	}
	return rec.fingerprint, rec.authMethod, true
}

// sweepLocked drops expired entries from every map. Called under s.mu on writes;
// the per-connection maps stay tiny (one auth window), so a full scan is cheap.
func (s *connStore) sweepLocked() {
	now := s.now()
	for k, rec := range s.memo {
		if !now.Before(rec.expires) {
			delete(s.memo, k)
		}
	}
	for k, rec := range s.host {
		if !now.Before(rec.expires) {
			delete(s.host, k)
		}
	}
	for k, rec := range s.sess {
		if !now.Before(rec.expires) {
			delete(s.sess, k)
		}
	}
}
