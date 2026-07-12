package proxyfront

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// fakeUpstream stands in for loopback sshpiperd: it REQUIREs a PROXY header
// (matching sshpiperd --allowed-proxy-addresses on loopback), records the
// re-emitted client source, counts accepts, and echoes payload.
type fakeUpstream struct {
	ln      net.Listener
	accepts int32
	sources chan string
}

func startUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	u := &fakeUpstream{
		ln:      &proxyproto.Listener{Listener: raw}, // DefaultPolicy REQUIRE
		sources: make(chan string, 4),
	}
	go func() {
		for {
			c, err := u.ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&u.accepts, 1)
			go func(c net.Conn) {
				defer c.Close()
				// RemoteAddr triggers header parse → re-emitted client source.
				u.sources <- c.RemoteAddr().String()
				_, _ = io.Copy(c, c) // echo
			}(c)
		}
	}()
	return u
}

func (u *fakeUpstream) addr() string { return u.ln.Addr().String() }
func (u *fakeUpstream) count() int32 { return atomic.LoadInt32(&u.accepts) }
func (u *fakeUpstream) Close()       { _ = u.ln.Close() }

// startShim launches a shim with the given trusted range in front of upstream.
func startShim(t *testing.T, upstream, trusted string) *Server {
	t.Helper()
	srv, err := Listen(Config{
		Listen:            "127.0.0.1:0",
		Upstream:          upstream,
		TrustedRanges:     []string{trusted},
		ReadHeaderTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// TestValidHeaderPipesAndPreservesClientIP is the happy path: a valid PROXY v2
// header from the trusted peer (127.0.0.1 here) is re-emitted to the upstream
// carrying the real client IP, and payload flows both ways.
func TestValidHeaderPipesAndPreservesClientIP(t *testing.T) {
	up := startUpstream(t)
	defer up.Close()
	shim := startShim(t, up.addr(), "127.0.0.1/32")

	c, err := net.Dial("tcp", shim.Addr().String())
	if err != nil {
		t.Fatalf("dial shim: %v", err)
	}
	defer c.Close()

	h := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("10.100.100.2"), Port: 22})
	if _, err := h.WriteTo(c); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := c.Write([]byte("hello-vm")); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	select {
	case src := <-up.sources:
		host, _, _ := net.SplitHostPort(src)
		if host != "203.0.113.7" {
			t.Fatalf("upstream saw client %q, want 203.0.113.7 (re-emit lost the real IP)", host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received a connection")
	}

	buf := make([]byte, 8)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello-vm" {
		t.Fatalf("echo: got %q want %q", buf, "hello-vm")
	}
}

// TestAbsentHeaderDropped is the core negative test: a connection from the peer
// that does not open with a PROXY header is dropped, and the upstream is never
// dialed (no SSH bytes, no fallback to the raw TCP source).
func TestAbsentHeaderDropped(t *testing.T) {
	up := startUpstream(t)
	defer up.Close()
	shim := startShim(t, up.addr(), "127.0.0.1/32")

	c, err := net.Dial("tcp", shim.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// Raw SSH-looking bytes, no PROXY header (>12 bytes so the signature check
	// can conclude "not PROXY").
	if _, err := c.Write([]byte("SSH-2.0-forged\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The shim must close us with no data.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 16)); err == nil && n > 0 {
		t.Fatalf("expected connection dropped, got %d bytes", n)
	}
	time.Sleep(100 * time.Millisecond)
	if up.count() != 0 {
		t.Fatalf("upstream was dialed for a headerless connection (count=%d)", up.count())
	}
}

// TestMalformedHeaderDropped: a truncated/garbled PROXY header from the peer is
// dropped and the upstream is never dialed.
func TestMalformedHeaderDropped(t *testing.T) {
	up := startUpstream(t)
	defer up.Close()
	shim := startShim(t, up.addr(), "127.0.0.1/32")

	c, err := net.Dial("tcp", shim.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// A valid header, truncated mid-way, then closed → parse failure.
	var buf bytes.Buffer
	h := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 1},
		&net.TCPAddr{IP: net.ParseIP("10.100.100.2"), Port: 22})
	_, _ = h.WriteTo(&buf)
	b := buf.Bytes()
	_, _ = c.Write(b[:len(b)/2])
	_ = c.Close()

	time.Sleep(200 * time.Millisecond)
	if up.count() != 0 {
		t.Fatalf("upstream was dialed for a malformed header (count=%d)", up.count())
	}
}

// TestNonPeerRejected: a source outside the trusted range is dropped by Accept
// even if it sends a well-formed header (peer-only ingress at the app layer;
// nftables enforces the same at the network layer).
func TestNonPeerRejected(t *testing.T) {
	up := startUpstream(t)
	defer up.Close()
	// Trust only 10.0.0.0/8; the test dials from 127.0.0.1 → non-peer.
	shim := startShim(t, up.addr(), "10.0.0.0/8")

	c, err := net.Dial("tcp", shim.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	h := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 1},
		&net.TCPAddr{IP: net.ParseIP("10.100.100.2"), Port: 22})
	_, _ = h.WriteTo(c)
	_, _ = c.Write([]byte("hello"))

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 16)); err == nil && n > 0 {
		t.Fatalf("expected drop for non-peer, got %d bytes", n)
	}
	time.Sleep(100 * time.Millisecond)
	if up.count() != 0 {
		t.Fatalf("upstream dialed for non-peer source (count=%d)", up.count())
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{Listen: "", Upstream: "x", TrustedRanges: []string{"10.0.0.0/8"}},
		{Listen: "x", Upstream: "", TrustedRanges: []string{"10.0.0.0/8"}},
		{Listen: "x", Upstream: "y", TrustedRanges: nil},
	}
	for i, cfg := range bad {
		if _, err := Listen(cfg); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
	// Invalid CIDR is rejected too.
	if _, err := Listen(Config{Listen: "127.0.0.1:0", Upstream: "x", TrustedRanges: []string{"not-a-cidr"}}); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}
