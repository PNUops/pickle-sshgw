package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"testing"

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

// fakeResolver records the last request and counts calls, returning a canned
// result/error.
type fakeResolver struct {
	route  *route.Route
	err    error
	gotReq route.Request
	calls  int
}

func (r *fakeResolver) Resolve(_ context.Context, req route.Request) (*route.Route, error) {
	r.calls++
	r.gotReq = req
	return r.route, r.err
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
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "student", HostKeys: []string{authLine}}}
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
	if u.GetHost() != "172.29.4.11" || u.GetPort() != 22 || u.GetUserName() != "student" {
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
	fr := &fakeResolver{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "student", HostKeys: []string{authLine}}}
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
	fr := &fakeResolver{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "student", HostKeys: []string{"x"}}}
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
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "student", HostKeys: []string{authLine}}}
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
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "student", HostKeys: []string{authLine}}}
	p := newPlugin(t, fr)
	conn := fakeConn{user: "team-alpha-a1b2", remote: "203.0.113.7:54321", uid: "conn-pw"}

	u, err := p.passwordCallback(conn, []byte("hunter2"))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if u.GetHost() != "172.29.4.11" || u.GetPort() != 22 || u.GetUserName() != "student" {
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
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "student", HostKeys: []string{authLine}}}
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
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "student", HostKeys: []string{pinnedLine}}}
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
	fr := &fakeResolver{route: &route.Route{IP: "1.2.3.4", Port: 22, User: "student", HostKeys: []string{"x"}}}
	p := newPlugin(t, fr)
	// No preceding route on this connection: fail-closed.
	if err := p.verifyHostKeyCallback(fakeConn{uid: "never-routed"}, "vm", "1.2.3.4:22", hostWire); err == nil {
		t.Fatal("expected fail-closed error when no host key was pinned")
	}
}

func TestPasswordCallback_TransportErrorFailsClosed(t *testing.T) {
	fr := &fakeResolver{err: errors.New("connection refused")}
	u, err := newPlugin(t, fr).passwordCallback(fakeConn{user: "slug", remote: "203.0.113.7:1"}, []byte("pw"))
	if u != nil || err == nil {
		t.Fatalf("expected fail-closed (nil upstream, error); got u=%+v err=%v", u, err)
	}
}

func TestConfigWiresAllThreeCallbacks(t *testing.T) {
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
