package gateway

import (
	"sort"
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

// sessionRecord remembers, per connection, every fingerprint that got an allowed
// route decision (the candidate set — publickey path) plus the auth method. It
// is a *set*, not a single "winner": sshpiper caches per-(user,key) callbacks and
// PipeStart does not reveal which key signed, so the plugin cannot single out the
// authenticator and must forward all candidates for the API's distinct-owner
// rule. authMethod is last-write-wins so a password fallback after a publickey
// probe is reported as password (candidates then suppressed).
type sessionRecord struct {
	fingerprints map[string]struct{}
	authMethod   string
	expires      time.Time
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

// addSessionCandidate adds a route-allowed fingerprint to the connection's
// publickey candidate set (accumulate, never overwrite — every allowed key is a
// candidate the API must weigh) and marks the method publickey.
func (s *connStore) addSessionCandidate(connID, fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	rec := s.sess[connID]
	if rec.fingerprints == nil {
		rec.fingerprints = make(map[string]struct{})
	}
	rec.fingerprints[fingerprint] = struct{}{}
	rec.authMethod = route.AuthPublicKey
	rec.expires = s.now().Add(s.ttl)
	s.sess[connID] = rec
}

// setSessionPassword marks the connection's authenticated method as password
// (no per-user identity). Last-write-wins over any earlier publickey mark, so a
// publickey probe followed by a password fallback is audited as password.
func (s *connStore) setSessionPassword(connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	rec := s.sess[connID]
	rec.authMethod = route.AuthPassword
	rec.expires = s.now().Add(s.ttl)
	s.sess[connID] = rec
}

// getSessionAttr returns the connection's candidate fingerprints (sorted, for a
// deterministic request) and auth method if present and unexpired.
func (s *connStore) getSessionAttr(connID string) (fingerprints []string, authMethod string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, present := s.sess[connID]
	if !present || !s.now().Before(rec.expires) {
		return nil, "", false
	}
	fps := make([]string, 0, len(rec.fingerprints))
	for fp := range rec.fingerprints {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	return fps, rec.authMethod, true
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
