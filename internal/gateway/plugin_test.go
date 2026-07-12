package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/pickle/sshgw/internal/route"
	"github.com/tg123/sshpiper/libplugin"
)

// fakeConn implements libplugin.ConnMetadata for callback tests.
type fakeConn struct {
	user   string
	remote string
}

func (f fakeConn) User() string              { return f.user }
func (f fakeConn) RemoteAddr() string        { return f.remote }
func (f fakeConn) UniqueID() string          { return "test-conn" }
func (f fakeConn) GetMeta(key string) string { return "" }

// fakeResolver records the last call and returns a canned result/error.
type fakeResolver struct {
	route    *route.Route
	err      error
	gotSlug  string
	gotSrcIP string
}

func (r *fakeResolver) Resolve(_ context.Context, slug, sourceIP string) (*route.Route, error) {
	r.gotSlug = slug
	r.gotSrcIP = sourceIP
	return r.route, r.err
}

func callback(p *Plugin) func(libplugin.ConnMetadata, []byte) (*libplugin.Upstream, error) {
	return p.Config().PasswordCallback
}

func TestPasswordCallback_SuccessPipesAndPassesPassword(t *testing.T) {
	fr := &fakeResolver{route: &route.Route{IP: "172.29.4.11", Port: 22, User: "student"}}
	cb := callback(New(fr))

	u, err := cb(fakeConn{user: "team-alpha-a1b2", remote: "203.0.113.7:54321"}, []byte("hunter2"))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	// Slug from username, source IP stripped of port.
	if fr.gotSlug != "team-alpha-a1b2" || fr.gotSrcIP != "203.0.113.7" {
		t.Fatalf("resolver args: slug=%q srcIP=%q", fr.gotSlug, fr.gotSrcIP)
	}
	// Upstream target from the route response.
	if u.GetHost() != "172.29.4.11" || u.GetPort() != 22 || u.GetUserName() != "student" {
		t.Fatalf("upstream: %+v", u)
	}
	if !u.GetIgnoreHostKey() {
		t.Error("v1 expects IgnoreHostKey=true (no per-VM host key yet)")
	}
	// Password passthrough: the client's typed password reaches the VM.
	if got := u.GetPassword().GetPassword(); got != "hunter2" {
		t.Fatalf("password passthrough: got %q want %q", got, "hunter2")
	}
}

func TestPasswordCallback_DenialRefuses(t *testing.T) {
	fr := &fakeResolver{err: &route.Denial{HTTPStatus: 403, Reason: "SSHGW_VM_BLOCKED"}}
	cb := callback(New(fr))

	u, err := cb(fakeConn{user: "slug", remote: "203.0.113.7:1"}, []byte("pw"))
	if u != nil {
		t.Fatalf("expected nil upstream on denial, got %+v", u)
	}
	var d *route.Denial
	if !errors.As(err, &d) || d.Machine() != "SSHGW_VM_BLOCKED" {
		t.Fatalf("expected SSHGW_VM_BLOCKED denial, got %v", err)
	}
}

func TestPasswordCallback_TransportErrorFailsClosed(t *testing.T) {
	fr := &fakeResolver{err: errors.New("connection refused")}
	cb := callback(New(fr))

	u, err := cb(fakeConn{user: "slug", remote: "203.0.113.7:1"}, []byte("pw"))
	if u != nil || err == nil {
		t.Fatalf("expected fail-closed (nil upstream, error); got u=%+v err=%v", u, err)
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
