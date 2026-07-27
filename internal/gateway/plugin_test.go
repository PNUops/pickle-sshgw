package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pickle/sshgw/internal/route"
	"golang.org/x/crypto/ssh"
)

// fakeConn implements libplugin.ConnMetadata for callback tests. uid defaults to
// "test-conn" so most tests need not set it; memoization tests vary it.
type fakeConn struct {
	user   string
	remote string
	uid    string
}

func (f fakeConn) User() string       { return f.user }
func (f fakeConn) RemoteAddr() string { return f.remote }
func (f fakeConn) UniqueID() string {
	if f.uid == "" {
		return "test-conn"
	}
	return f.uid
}
func (f fakeConn) GetMeta(string) string { return "" }

// fakeResolver records the last route request and counts calls, and separately
// captures session-audit calls (guarded by a mutex — sendSessionAudit runs in a
// goroutine). Returns canned results/errors.
type fakeResolver struct {
	route  *route.Route
	err    error
	gotReq route.Request
	calls  int

	sessMu   sync.Mutex
	sessReqs []route.SessionRequest
	sessErr  error
	sessCh   chan struct{} // if set, receives one signal per SessionStart call
}

func (r *fakeResolver) Resolve(_ context.Context, req route.Request) (*route.Route, error) {
	r.calls++
	r.gotReq = req
	return r.route, r.err
}

func (r *fakeResolver) SessionStart(_ context.Context, req route.SessionRequest) error {
	r.sessMu.Lock()
	r.sessReqs = append(r.sessReqs, req)
	ch, err := r.sessCh, r.sessErr
	r.sessMu.Unlock()
	if ch != nil {
		ch <- struct{}{}
	}
	return err
}

func (r *fakeResolver) sessionCalls() []route.SessionRequest {
	r.sessMu.Lock()
	defer r.sessMu.Unlock()
	return append([]route.SessionRequest(nil), r.sessReqs...)
}

// goldenSeed is the fixed 32-byte ed25519 seed (bytes 1..32) whose public key's
// OpenSSH SHA-256 fingerprint is the golden value asserted below.
func goldenSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

// goldenFingerprint was produced from the goldenSeed key and cross-checked with
// the OpenSSH tool:
//
//	$ ssh-keygen -lf goldkey.pub
//	256 SHA256:eVkCKHnc5RjanBduU2vmOecbFl3M9wOgHdk24INJytY no comment (ED25519)
//
// It equals Go's ssh.FingerprintSHA256 of the same key — the join key the route
// API computes at registration, so all three agree.
const goldenFingerprint = "SHA256:eVkCKHnc5RjanBduU2vmOecbFl3M9wOgHdk24INJytY"

// userKeyWire returns the SSH wire-format blob of the golden user public key —
// the exact bytes sshpiperd hands the PublicKeyCallback (key.Marshal()).
func userKeyWire(t *testing.T) []byte {
	t.Helper()
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(goldenSeed()).Public())
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return pub.Marshal()
}

// hostKeyMaterial builds a distinct host key: its authorized_keys one-line form
// (as the route response carries it) and its wire blob (as VerifyHostKeyCallback
// receives it).
func hostKeyMaterial(t *testing.T, seedByte byte) (authLine string, wire []byte) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	line := bytes.TrimSpace(ssh.MarshalAuthorizedKey(pub))
	return string(line), pub.Marshal()
}

// testPlatformKey returns a valid ed25519 private key PEM for New().
func testPlatformKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "test-platform")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(blk)
}

func newPlugin(t *testing.T, fr *fakeResolver) *Plugin {
	t.Helper()
	return New(fr, testPlatformKey(t))
}

func TestPublicKeyCallback_Success(t *testing.T) {
	authLine, _ := hostKeyMaterial(t, 0x40)
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}}}
	platformKey := testPlatformKey(t)
	p := New(fr, platformKey)

	u, err := p.publicKeyCallback(fakeConn{user: "team-alpha-a1b2", remote: "203.0.113.7:54321"}, userKeyWire(t))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	// Request carried the publickey method, the golden fingerprint, and the
	// connection id (never the key blob).
	if fr.gotReq.AuthMethod != route.AuthPublicKey {
		t.Errorf("authMethod: got %q", fr.gotReq.AuthMethod)
	}
	if fr.gotReq.PublicKeyFingerprint != goldenFingerprint {
		t.Errorf("fingerprint: got %q want %q", fr.gotReq.PublicKeyFingerprint, goldenFingerprint)
	}
	if fr.gotReq.Slug != "team-alpha-a1b2" || fr.gotReq.SourceIP != "203.0.113.7" {
		t.Errorf("slug/sourceIp: %+v", fr.gotReq)
	}
	if fr.gotReq.ConnectionID != "test-conn" {
		t.Errorf("connectionId: got %q", fr.gotReq.ConnectionID)
	}
	// Upstream target from the route, host-key verification ON.
	if u.GetHost() != "172.29.4.11" || u.GetPort() != 22 || u.GetUserName() != "ubuntu" {
		t.Fatalf("upstream: %+v", u)
	}
	if u.GetIgnoreHostKey() {
		t.Error("IgnoreHostKey must be false in v2 (host key is pinned)")
	}
	// Upstream auth is the platform private key, not a password.
	if got := u.GetPrivateKey().GetPrivateKey(); !bytes.Equal(got, platformKey) {
		t.Errorf("upstream auth is not the platform private key")
	}
	if u.GetPassword() != nil {
		t.Error("publickey path must not carry a password auth")
	}
}

// The exact fingerprint the plugin computes must match the golden value — the
// contract's join key between sshpiperd, the API, and ssh-keygen.
func TestPublicKeyCallback_FingerprintGolden(t *testing.T) {
	authLine, _ := hostKeyMaterial(t, 0x40)
	fr := &fakeResolver{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "ubuntu", HostKeys: []string{authLine}}}
	if _, err := newPlugin(t, fr).publicKeyCallback(fakeConn{user: "slug", remote: "203.0.113.7:1"}, userKeyWire(t)); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if fr.gotReq.PublicKeyFingerprint != goldenFingerprint {
		t.Fatalf("fingerprint: got %q want %q", fr.gotReq.PublicKeyFingerprint, goldenFingerprint)
	}
}

func TestPublicKeyCallback_DenialRefuses(t *testing.T) {
	fr := &fakeResolver{err: &route.Denial{HTTPStatus: 403, Reason: "SSHGW_KEY_UNKNOWN"}}
	u, err := newPlugin(t, fr).publicKeyCallback(fakeConn{user: "slug", remote: "203.0.113.7:1"}, userKeyWire(t))
	if u != nil {
		t.Fatalf("expected nil upstream on denial, got %+v", u)
	}
	var d *route.Denial
	if !errors.As(err, &d) || d.Machine() != "SSHGW_KEY_UNKNOWN" {
		t.Fatalf("expected SSHGW_KEY_UNKNOWN denial, got %v", err)
	}
}

func TestPublicKeyCallback_MalformedKeyFailsClosed(t *testing.T) {
	fr := &fakeResolver{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "ubuntu", HostKeys: []string{"x"}}}
	u, err := newPlugin(t, fr).publicKeyCallback(fakeConn{user: "slug", remote: "203.0.113.7:1"}, []byte("not-a-key"))
	if u != nil || err == nil {
		t.Fatalf("expected fail-closed on malformed key; got u=%+v err=%v", u, err)
	}
	if fr.calls != 0 {
		t.Errorf("resolver must not be called for an unparseable key; calls=%d", fr.calls)
	}
}

// A client offers each key twice (probe, then signed). The same (conn,key) must
// cost exactly one API call.
func TestPublicKeyCallback_MemoizesProbeAndSign(t *testing.T) {
	authLine, _ := hostKeyMaterial(t, 0x40)
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-memo"}
	key := userKeyWire(t)

	u1, err1 := p.publicKeyCallback(conn, key)
	u2, err2 := p.publicKeyCallback(conn, key)
	if err1 != nil || err2 != nil {
		t.Fatalf("callbacks: %v %v", err1, err2)
	}
	if fr.calls != 1 {
		t.Errorf("expected 1 resolver call for probe+signed, got %d", fr.calls)
	}
	if u1.GetHost() != u2.GetHost() {
		t.Errorf("memoized upstream differs: %q vs %q", u1.GetHost(), u2.GetHost())
	}
}

// A structural denial is stable for the auth window and IS memoized: re-offering
// the same key costs one API call.
func TestPublicKeyCallback_DenialMemoized(t *testing.T) {
	fr := &fakeResolver{err: &route.Denial{HTTPStatus: 403, Reason: "SSHGW_KEY_NOT_MEMBER"}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-deny-memo"}
	key := userKeyWire(t)
	_, _ = p.publicKeyCallback(conn, key)
	_, _ = p.publicKeyCallback(conn, key)
	if fr.calls != 1 {
		t.Errorf("a denial should be memoized: expected 1 resolver call, got %d", fr.calls)
	}
}

// A transport/decode blip is NOT memoized: the client's signed-stage retry must
// re-hit the API rather than be pinned to the cached failure for the auth window.
func TestPublicKeyCallback_TransportErrorNotMemoized(t *testing.T) {
	fr := &fakeResolver{err: errors.New("connection refused")}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-blip"}
	key := userKeyWire(t)
	if _, err := p.publicKeyCallback(conn, key); err == nil {
		t.Fatal("expected error")
	}
	if _, err := p.publicKeyCallback(conn, key); err == nil {
		t.Fatal("expected error")
	}
	if fr.calls != 2 {
		t.Errorf("a transport error must not be memoized: expected 2 resolver calls, got %d", fr.calls)
	}
}

func TestPasswordCallback_DisabledDenied(t *testing.T) {
	fr := &fakeResolver{err: &route.Denial{HTTPStatus: 403, Reason: "SSHGW_PASSWORD_DISABLED"}}
	u, err := newPlugin(t, fr).passwordCallback(fakeConn{user: "slug", remote: "203.0.113.7:1"}, []byte("pw"))
	if u != nil {
		t.Fatalf("expected nil upstream, got %+v", u)
	}
	var d *route.Denial
	if !errors.As(err, &d) || d.Machine() != "SSHGW_PASSWORD_DISABLED" {
		t.Fatalf("expected SSHGW_PASSWORD_DISABLED denial, got %v", err)
	}
	if fr.gotReq.AuthMethod != route.AuthPassword {
		t.Errorf("authMethod: got %q want password", fr.gotReq.AuthMethod)
	}
}

func TestPasswordCallback_OptInPassesThroughWithHostKeyPin(t *testing.T) {
	authLine, hostWire := hostKeyMaterial(t, 0x55)
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "team-alpha-a1b2", remote: "203.0.113.7:54321", uid: "conn-pw"}

	u, err := p.passwordCallback(conn, []byte("hunter2"))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if u.GetHost() != "172.29.4.11" || u.GetPort() != 22 || u.GetUserName() != "ubuntu" {
		t.Fatalf("upstream: %+v", u)
	}
	// v2: host key pinned, no longer ignored (v1 asserted IgnoreHostKey:true).
	if u.GetIgnoreHostKey() {
		t.Error("IgnoreHostKey must be false in v2")
	}
	if got := u.GetPassword().GetPassword(); got != "hunter2" {
		t.Fatalf("password passthrough: got %q want %q", got, "hunter2")
	}
	// The route's host keys were pinned for this connection: verify succeeds.
	if err := p.verifyHostKeyCallback(conn, "vm", "172.29.4.11:22", hostWire); err != nil {
		t.Errorf("host key should verify after successful route: %v", err)
	}
}

func TestVerifyHostKey_Match(t *testing.T) {
	authLine, hostWire := hostKeyMaterial(t, 0x11)
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-match"}
	if _, err := p.publicKeyCallback(conn, userKeyWire(t)); err != nil {
		t.Fatalf("route: %v", err)
	}
	if err := p.verifyHostKeyCallback(conn, "vm", "172.29.4.11:22", hostWire); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestVerifyHostKey_Mismatch(t *testing.T) {
	pinnedLine, _ := hostKeyMaterial(t, 0x11)
	_, otherWire := hostKeyMaterial(t, 0x22) // a different host key
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{pinnedLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-mismatch"}
	if _, err := p.publicKeyCallback(conn, userKeyWire(t)); err != nil {
		t.Fatalf("route: %v", err)
	}
	if err := p.verifyHostKeyCallback(conn, "vm", "172.29.4.11:22", otherWire); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestVerifyHostKey_MissingEntry(t *testing.T) {
	_, hostWire := hostKeyMaterial(t, 0x11)
	fr := &fakeResolver{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "ubuntu", HostKeys: []string{"x"}}}
	p := newPlugin(t, fr)
	// No preceding route on this connection: fail-closed.
	if err := p.verifyHostKeyCallback(fakeConn{uid: "never-routed"}, "vm", "1.2.3.4:22", hostWire); err == nil {
		t.Fatal("expected fail-closed error when no host key was pinned")
	}
}

// Regression guard for deploy blocker A / Option B: sshpiper v1.5.4 gives the
// plugin no way to force the upstream host-key algorithm (the libplugin Upstream
// has no HostKeyAlgorithms field, and createUpstream never sets one), and Go's
// default preference ranks ecdsa-nistp256 above ed25519 — so a VM holding both
// keys presents ecdsa on the upstream hop. The API therefore pins ALL of the
// VM's host key types, and verifyHostKey must match the presented key against
// any pinned entry regardless of algorithm.
func TestVerifyHostKey_MixedTypeArray(t *testing.T) {
	edLine, _ := hostKeyMaterial(t, 0x31) // ed25519 pinned entry
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	ecPub, err := ssh.NewPublicKey(ecKey.Public())
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	ecLine := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(ecPub))) // ecdsa pinned entry

	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu",
		HostKeys: []string{edLine, ecLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-mixed"}
	if _, err := p.publicKeyCallback(conn, userKeyWire(t)); err != nil {
		t.Fatalf("route: %v", err)
	}
	// The upstream negotiates ecdsa (Go default) → the ecdsa entry must verify.
	if err := p.verifyHostKeyCallback(conn, "vm", "172.29.4.11:22", ecPub.Marshal()); err != nil {
		t.Fatalf("ecdsa host key should match the ecdsa array entry: %v", err)
	}
	// A key of a type/value absent from the pinned set is still refused.
	_, strangerWire := hostKeyMaterial(t, 0x99)
	if err := p.verifyHostKeyCallback(conn, "vm", "172.29.4.11:22", strangerWire); err == nil {
		t.Fatal("a key absent from the pinned array must be refused")
	}
}

// A resolver that returns (nil, nil) violates the route.Client contract; both
// callbacks must still refuse rather than panic on the nil route.
func TestCallbacks_NilRouteNilErrFailsClosed(t *testing.T) {
	fr := &fakeResolver{route: nil, err: nil}
	p := newPlugin(t, fr)
	if u, err := p.publicKeyCallback(fakeConn{user: "slug", remote: "203.0.113.7:1"}, userKeyWire(t)); u != nil || err == nil {
		t.Errorf("publickey: expected fail-closed, got u=%+v err=%v", u, err)
	}
	if u, err := p.passwordCallback(fakeConn{user: "slug", remote: "203.0.113.7:1"}, []byte("pw")); u != nil || err == nil {
		t.Errorf("password: expected fail-closed, got u=%+v err=%v", u, err)
	}
}

func TestPasswordCallback_TransportErrorFailsClosed(t *testing.T) {
	fr := &fakeResolver{err: errors.New("connection refused")}
	u, err := newPlugin(t, fr).passwordCallback(fakeConn{user: "slug", remote: "203.0.113.7:1"}, []byte("pw"))
	if u != nil || err == nil {
		t.Fatalf("expected fail-closed (nil upstream, error); got u=%+v err=%v", u, err)
	}
}

func TestConfigWiresCallbacks(t *testing.T) {
	cfg := newPlugin(t, &fakeResolver{}).Config()
	if cfg.PublicKeyCallback == nil {
		t.Error("PublicKeyCallback not wired")
	}
	if cfg.PasswordCallback == nil {
		t.Error("PasswordCallback not wired")
	}
	if cfg.VerifyHostKeyCallback == nil {
		t.Error("VerifyHostKeyCallback not wired")
	}
	if cfg.PipeStartCallback == nil {
		t.Error("PipeStartCallback not wired")
	}
}

// userKeyForSeed builds an arbitrary distinct ed25519 user key: its wire blob
// (as PublicKeyCallback receives it) and its OpenSSH SHA-256 fingerprint.
func userKeyForSeed(t *testing.T, seedByte byte) (wire []byte, fingerprint string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return pub.Marshal(), ssh.FingerprintSHA256(pub)
}

// After a single successful publickey auth, the session-audit request carries
// exactly that one fingerprint as the sole candidate, plus connection context.
func TestBuildSessionRequest_PublicKey(t *testing.T) {
	authLine, _ := hostKeyMaterial(t, 0x40)
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "team-alpha-a1b2", remote: "203.0.113.7:54321", uid: "conn-pk"}
	if _, err := p.publicKeyCallback(conn, userKeyWire(t)); err != nil {
		t.Fatalf("route: %v", err)
	}
	req, ok := p.buildSessionRequest(conn)
	if !ok {
		t.Fatal("expected attribution after successful publickey auth")
	}
	if req.AuthMethod != route.AuthPublicKey {
		t.Errorf("authMethod: got %q", req.AuthMethod)
	}
	if len(req.CandidateFingerprints) != 1 || req.CandidateFingerprints[0] != goldenFingerprint {
		t.Errorf("expected single candidate [%s], got %+v", goldenFingerprint, req.CandidateFingerprints)
	}
	if req.Slug != "team-alpha-a1b2" || req.SourceIP != "203.0.113.7" || req.ConnectionID != "conn-pk" {
		t.Errorf("bad session context: %+v", req)
	}
}

// Every route-allowed key on a connection accumulates into the candidate set —
// this is what lets the API apply the distinct-owner rule (a framing offer of a
// fellow member's key shows up as a second candidate, never silently overwriting
// the real key).
func TestBuildSessionRequest_MultipleCandidatesAccumulate(t *testing.T) {
	authLine, _ := hostKeyMaterial(t, 0x40)
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-multi"}

	keyA := userKeyWire(t) // golden
	keyB, fpB := userKeyForSeed(t, 0x77)
	if _, err := p.publicKeyCallback(conn, keyA); err != nil {
		t.Fatalf("keyA: %v", err)
	}
	if _, err := p.publicKeyCallback(conn, keyB); err != nil {
		t.Fatalf("keyB: %v", err)
	}

	req, ok := p.buildSessionRequest(conn)
	if !ok {
		t.Fatal("expected attribution")
	}
	got := map[string]bool{}
	for _, fp := range req.CandidateFingerprints {
		got[fp] = true
	}
	if len(req.CandidateFingerprints) != 2 || !got[goldenFingerprint] || !got[fpB] {
		t.Fatalf("expected both candidates {%s, %s}, got %+v", goldenFingerprint, fpB, req.CandidateFingerprints)
	}
}

// A password session records the method with no candidates (actor=null audit),
// even if an earlier publickey candidate was offered (last-write-wins).
func TestBuildSessionRequest_Password(t *testing.T) {
	authLine, _ := hostKeyMaterial(t, 0x55)
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-pw"}
	// A publickey candidate offered first must not leak into a password session.
	if _, err := p.publicKeyCallback(conn, userKeyWire(t)); err != nil {
		t.Fatalf("publickey: %v", err)
	}
	if _, err := p.passwordCallback(conn, []byte("pw")); err != nil {
		t.Fatalf("password: %v", err)
	}
	req, ok := p.buildSessionRequest(conn)
	if !ok {
		t.Fatal("expected attribution after successful password auth")
	}
	if req.AuthMethod != route.AuthPassword || len(req.CandidateFingerprints) != 0 {
		t.Errorf("password session must carry no candidates: %+v", req)
	}
}

// A connection that never authenticated has no attribution: PipeStart must skip.
func TestBuildSessionRequest_NoAttribution(t *testing.T) {
	if _, ok := newPlugin(t, &fakeResolver{}).buildSessionRequest(fakeConn{uid: "never-authed"}); ok {
		t.Fatal("expected no attribution for a never-authenticated connection")
	}
}

// End to end: PipeStart fires the session audit with the stored fingerprint.
func TestPipeStart_EmitsSessionAudit(t *testing.T) {
	authLine, _ := hostKeyMaterial(t, 0x40)
	fr := &fakeResolver{
		route:  &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}},
		sessCh: make(chan struct{}, 1),
	}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "team-alpha-a1b2", remote: "203.0.113.7:54321", uid: "conn-e2e"}
	if _, err := p.publicKeyCallback(conn, userKeyWire(t)); err != nil {
		t.Fatalf("route: %v", err)
	}

	p.pipeStartCallback(conn)
	select {
	case <-fr.sessCh:
	case <-time.After(2 * time.Second):
		t.Fatal("SessionStart was not called within timeout")
	}
	calls := fr.sessionCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 session call, got %d", len(calls))
	}
	if len(calls[0].CandidateFingerprints) != 1 || calls[0].CandidateFingerprints[0] != goldenFingerprint ||
		calls[0].ConnectionID != "conn-e2e" {
		t.Errorf("bad session audit request: %+v", calls[0])
	}
}

// PipeStart on a connection with no attribution must not call SessionStart and
// must not spawn work (deterministic: buildSessionRequest returns ok=false).
func TestPipeStart_NoAttributionSkips(t *testing.T) {
	fr := &fakeResolver{}
	newPlugin(t, fr).pipeStartCallback(fakeConn{uid: "never-authed"})
	if got := len(fr.sessionCalls()); got != 0 {
		t.Fatalf("expected no session call for unattributed connection, got %d", got)
	}
}

// A failing session audit must neither panic nor affect the session; the
// goroutine logs and returns.
func TestPipeStart_SessionFailureIsHarmless(t *testing.T) {
	authLine, _ := hostKeyMaterial(t, 0x40)
	fr := &fakeResolver{
		route:   &route.Route{IP: "172.29.4.11", Port: 22, User: "ubuntu", HostKeys: []string{authLine}},
		sessErr: errors.New("api down"),
		sessCh:  make(chan struct{}, 1),
	}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "slug", remote: "203.0.113.7:1", uid: "conn-fail"}
	if _, err := p.publicKeyCallback(conn, userKeyWire(t)); err != nil {
		t.Fatalf("route: %v", err)
	}
	p.pipeStartCallback(conn) // must return immediately regardless of audit outcome
	select {
	case <-fr.sessCh:
	case <-time.After(2 * time.Second):
		t.Fatal("SessionStart was not attempted")
	}
	// Reaching here without panic is the assertion.
}

func TestHostFromAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:54321": "203.0.113.7",
		"203.0.113.7":       "203.0.113.7",
		"[2001:db8::1]:22":  "2001:db8::1",
		"":                  "",
	}
	for in, want := range cases {
		if got := hostFromAddr(in); got != want {
			t.Errorf("hostFromAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
