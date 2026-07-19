package terminal

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"
)

const testOrigin = "https://pickle.pnuops.com"

// testBridge wires a Bridge over a fakeAPI and a fakeVM, served on an httptest
// server. cfgMut lets a test tweak timing knobs before Validate.
func testBridge(t *testing.T, vmOpts fakeVMOpts, cfgMut func(*Config)) (*Bridge, *fakeAPI, *fakeVM, *httptest.Server) {
	t.Helper()
	api := startFakeAPI(t)
	vm := startFakeVM(t, vmOpts)
	host, portStr, err := net.SplitHostPort(vm.addr)
	if err != nil {
		t.Fatalf("split VM addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	api.redeemResult = RedeemResult{
		SessionID: "sess-1", UserID: 7, VMID: 9,
		VMIp: host, Port: port, User: "student",
		HostKeys: []string{vm.hostKeyLine},
	}
	cfg := Config{
		APIBase: api.baseURL(), GatewayToken: "gtok", ControlToken: "ctok",
		ConsoleOrigin: testOrigin, TerminalKeyFile: "unused-in-test",
		WSAllowedSourceIP: "127.0.0.1", ControlAllowedSourceIP: "127.0.0.1",
		// Fast-but-not-flappy defaults; individual tests override.
		IdleTimeout: 10 * time.Second, PingInterval: 10 * time.Second,
		RevalidateInterval: 10 * time.Second, SSHConnectTimeout: 5 * time.Second,
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	b := NewBridge(cfg, newTestSigner(t), NewAPIClient(cfg.APIBase, cfg.GatewayToken, cfg.APITimeout))
	ts := httptest.NewServer(b.WSHandler())
	t.Cleanup(ts.Close)
	return b, api, vm, ts
}

// dialRaw performs the WS handshake with explicit Origin, X-Real-IP and offered
// subprotocols. It returns the conn (or the error, for handshake rejections).
func dialRaw(t *testing.T, ts *httptest.Server, origin, realIP string, subprotocols []string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	u := "ws" + strings.TrimPrefix(ts.URL, "http") + "/terminal/ws"
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	if realIP != "" {
		h.Set("X-Real-IP", realIP)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: h, Subprotocols: subprotocols})
}

// wsClient wraps a dialed conn with a background reader that classifies frames.
type wsClient struct {
	conn      *websocket.Conn
	closeCode chan websocket.StatusCode
	binary    chan []byte
	exit      chan exitFrame
}

func connect(t *testing.T, ts *httptest.Server, ticket string) *wsClient {
	t.Helper()
	conn, _, err := dialRaw(t, ts, testOrigin, "203.0.113.7",
		[]string{Subprotocol, ticketPrefix + ticket})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if conn.Subprotocol() != Subprotocol {
		t.Fatalf("negotiated subprotocol = %q, want %q (ticket element must not be echoed)", conn.Subprotocol(), Subprotocol)
	}
	c := &wsClient{
		conn:      conn,
		closeCode: make(chan websocket.StatusCode, 1),
		binary:    make(chan []byte, 256),
		exit:      make(chan exitFrame, 4),
	}
	go c.readLoop()
	return c
}

func (c *wsClient) readLoop() {
	for {
		typ, data, err := c.conn.Read(context.Background())
		if err != nil {
			c.closeCode <- websocket.CloseStatus(err)
			return
		}
		switch typ {
		case websocket.MessageBinary:
			select {
			case c.binary <- data:
			default:
			}
		case websocket.MessageText:
			var ef exitFrame
			if json.Unmarshal(data, &ef) == nil && ef.Type == "exit" {
				select {
				case c.exit <- ef:
				default:
				}
			}
		}
	}
}

func (c *wsClient) send(data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.conn.Write(ctx, websocket.MessageBinary, data)
}

func (c *wsClient) sendText(data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.conn.Write(ctx, websocket.MessageText, data)
}

func (c *wsClient) awaitClose(t *testing.T, d time.Duration) websocket.StatusCode {
	t.Helper()
	select {
	case code := <-c.closeCode:
		return code
	case <-time.After(d):
		t.Fatalf("timed out waiting for WS close")
		return 0
	}
}

func (c *wsClient) awaitBinaryContains(t *testing.T, want string, d time.Duration) {
	t.Helper()
	var acc []byte
	deadline := time.After(d)
	for {
		select {
		case b := <-c.binary:
			acc = append(acc, b...)
			if bytes.Contains(acc, []byte(want)) {
				return
			}
		case <-deadline:
			t.Fatalf("did not receive %q; got %q", want, acc)
		}
	}
}

// waitEndCount polls the fakeAPI until it has recorded n session-end calls, or
// fails after the deadline.
func waitEndCount(t *testing.T, api *fakeAPI, n int, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		if api.endCount() >= n {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("session-end count = %d, want %d (reasons=%v)", api.endCount(), n, api.endReasons())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// --- tests -----------------------------------------------------------------

func TestBridge_EchoRoundtripAndSessionEndOnce(t *testing.T) {
	_, api, _, ts := testBridge(t, fakeVMOpts{}, nil)
	c := connect(t, ts, "tok-echo")

	if err := c.send([]byte("hello\n")); err != nil {
		t.Fatalf("send: %v", err)
	}
	c.awaitBinaryContains(t, "hello\n", 3*time.Second)

	// session-start recorded with the X-Real-IP client IP.
	if len(api.sessionStarts) != 1 || api.sessionStarts[0].ClientIP != "203.0.113.7" {
		t.Fatalf("session-start not recorded correctly: %+v", api.sessionStarts)
	}

	// Client closes → session-end CLIENT_CLOSED, exactly once.
	_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
	waitEndCount(t, api, 1, 3*time.Second)
	time.Sleep(100 * time.Millisecond) // allow any erroneous second report
	if api.endCount() != 1 {
		t.Fatalf("session-end must fire exactly once, got %d", api.endCount())
	}
	if api.sessionEnds[0].Reason != EndClientClosed {
		t.Fatalf("end reason = %q, want CLIENT_CLOSED", api.sessionEnds[0].Reason)
	}
	if api.sessionEnds[0].BytesIn == 0 || api.sessionEnds[0].BytesOut == 0 {
		t.Fatalf("byte counts should be non-zero: %+v", api.sessionEnds[0])
	}
}

func TestBridge_OriginMismatchRejected(t *testing.T) {
	_, _, _, ts := testBridge(t, fakeVMOpts{}, nil)
	_, resp, err := dialRaw(t, ts, "https://evil.example", "203.0.113.7",
		[]string{Subprotocol, "ticket.x"})
	if err == nil {
		t.Fatal("expected handshake rejection on Origin mismatch")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestBridge_SourceIPRejected(t *testing.T) {
	_, _, _, ts := testBridge(t, fakeVMOpts{}, func(c *Config) {
		c.WSAllowedSourceIP = "10.9.8.7" // not 127.0.0.1
	})
	_, resp, err := dialRaw(t, ts, testOrigin, "203.0.113.7",
		[]string{Subprotocol, "ticket.x"})
	if err == nil {
		t.Fatal("expected handshake rejection on source IP mismatch")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestBridge_MalformedSubprotocolRejected(t *testing.T) {
	_, _, _, ts := testBridge(t, fakeVMOpts{}, nil)
	// Only the fixed name, no ticket element.
	_, _, err := dialRaw(t, ts, testOrigin, "203.0.113.7", []string{Subprotocol})
	if err == nil {
		t.Fatal("expected rejection when ticket element is absent")
	}
}

func TestBridge_TicketNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	old := log.StandardLogger().Out
	oldLevel := log.GetLevel()
	log.SetOutput(&buf)
	log.SetLevel(log.DebugLevel)
	defer func() { log.SetOutput(old); log.SetLevel(oldLevel) }()

	_, api, _, ts := testBridge(t, fakeVMOpts{}, nil)
	const ticket = "SUPERSECRETTICKET-9f3c1a2e"
	c := connect(t, ts, ticket)
	_ = c.send([]byte("x\n"))
	c.awaitBinaryContains(t, "x", 3*time.Second)
	_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
	waitEndCount(t, api, 1, 3*time.Second)

	if strings.Contains(buf.String(), ticket) {
		t.Fatalf("ticket leaked into logs:\n%s", buf.String())
	}
}

func TestBridge_RedeemDenyMapping(t *testing.T) {
	cases := []struct {
		reason string
		want   websocket.StatusCode
	}{
		{reasonTicketInvalid, closeTicketInvalid},
		{reasonVMNotRunning, closeVMNotRunning},
		{reasonAccessRevoked, closeAccessRevoked},
		{reasonTerminalDisabled, closeDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			_, api, _, ts := testBridge(t, fakeVMOpts{}, nil)
			api.redeemReason = tc.reason
			c := connect(t, ts, "tok")
			// exit frame carries the mapped code, then the WS closes with it.
			select {
			case ef := <-c.exit:
				if ef.Code != int(tc.want) {
					t.Fatalf("exit frame code = %d, want %d", ef.Code, int(tc.want))
				}
				if ef.Message == "" {
					t.Fatal("exit frame message must be non-empty Korean text")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no exit frame")
			}
			if got := c.awaitClose(t, 3*time.Second); got != tc.want {
				t.Fatalf("close code = %d, want %d", got, tc.want)
			}
			// A redeem deny never starts a session, so no session-start/end.
			if len(api.sessionStarts) != 0 {
				t.Fatalf("deny must not start a session: %+v", api.sessionStarts)
			}
		})
	}
}

func TestBridge_RedeemTransportErrorClosesMaintenance(t *testing.T) {
	_, api, _, ts := testBridge(t, fakeVMOpts{}, nil)
	api.redeemStatusOverride = http.StatusInternalServerError
	c := connect(t, ts, "tok")
	if got := c.awaitClose(t, 3*time.Second); got != closeMaintenance {
		t.Fatalf("close code = %d, want 1001", got)
	}
}

func TestBridge_Resize(t *testing.T) {
	_, api, vm, ts := testBridge(t, fakeVMOpts{}, nil)
	c := connect(t, ts, "tok")
	// Ensure the session is up before resizing.
	_ = c.send([]byte("hi\n"))
	c.awaitBinaryContains(t, "hi", 3*time.Second)

	msg, _ := json.Marshal(controlMessage{Type: "resize", Cols: 132, Rows: 43})
	if err := c.sendText(msg); err != nil {
		t.Fatalf("send resize: %v", err)
	}
	select {
	case got := <-vm.resizeCh:
		if got[0] != 132 || got[1] != 43 {
			t.Fatalf("resize = %v, want [132 43]", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no window-change on the VM")
	}
	_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
	waitEndCount(t, api, 1, 3*time.Second)
}

func TestBridge_IdleTimeout_InputOnlyResets(t *testing.T) {
	// No input → idle closes 4001.
	t.Run("fires_without_input", func(t *testing.T) {
		_, api, _, ts := testBridge(t, fakeVMOpts{}, func(c *Config) {
			c.IdleTimeout = 250 * time.Millisecond
		})
		c := connect(t, ts, "tok")
		if got := c.awaitClose(t, 3*time.Second); got != closeIdle {
			t.Fatalf("close code = %d, want 4001", got)
		}
		waitEndCount(t, api, 1, 2*time.Second)
		if api.sessionEnds[0].Reason != EndIdleTimeout {
			t.Fatalf("end reason = %q, want IDLE_TIMEOUT", api.sessionEnds[0].Reason)
		}
	})

	// Resize frames do NOT reset idle → still closes 4001.
	t.Run("resize_does_not_reset", func(t *testing.T) {
		_, _, _, ts := testBridge(t, fakeVMOpts{}, func(c *Config) {
			c.IdleTimeout = 300 * time.Millisecond
		})
		c := connect(t, ts, "tok")
		stop := make(chan struct{})
		go func() {
			msg, _ := json.Marshal(controlMessage{Type: "resize", Cols: 80, Rows: 24})
			tk := time.NewTicker(80 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tk.C:
					_ = c.sendText(msg)
				}
			}
		}()
		got := c.awaitClose(t, 3*time.Second)
		close(stop)
		if got != closeIdle {
			t.Fatalf("close code = %d, want 4001 (resize must not reset idle)", got)
		}
	})

	// Binary input DOES reset idle → the session stays alive across the window.
	t.Run("input_resets", func(t *testing.T) {
		_, _, _, ts := testBridge(t, fakeVMOpts{}, func(c *Config) {
			c.IdleTimeout = 300 * time.Millisecond
		})
		c := connect(t, ts, "tok")
		deadline := time.After(700 * time.Millisecond) // > 2× idle
		tk := time.NewTicker(90 * time.Millisecond)
		defer tk.Stop()
	loop:
		for {
			select {
			case <-deadline:
				break loop
			case code := <-c.closeCode:
				t.Fatalf("session closed early (%d) — input should reset idle", code)
			case <-tk.C:
				if err := c.send([]byte("x")); err != nil {
					t.Fatalf("send: %v", err)
				}
			}
		}
	})
}

func TestBridge_RevalidateDenyCloses(t *testing.T) {
	_, api, _, ts := testBridge(t, fakeVMOpts{}, func(c *Config) {
		c.RevalidateInterval = 120 * time.Millisecond
	})
	api.revalidateFn = func(int64) (bool, string) { return false, reasonAccessRevoked }
	c := connect(t, ts, "tok")
	if got := c.awaitClose(t, 3*time.Second); got != closeAccessRevoked {
		t.Fatalf("close code = %d, want 4004", got)
	}
	waitEndCount(t, api, 1, 2*time.Second)
	if api.sessionEnds[0].Reason != EndRevalidationDenied {
		t.Fatalf("end reason = %q, want REVALIDATION_DENIED", api.sessionEnds[0].Reason)
	}
}

// A prolonged run of revalidation transport errors must eventually close the
// session (bounded fail-open) so it cannot outlive api-mediated revocation.
func TestBridge_RevalidateConsecutiveFailuresClose(t *testing.T) {
	_, api, _, ts := testBridge(t, fakeVMOpts{}, func(c *Config) {
		c.RevalidateInterval = 50 * time.Millisecond
		c.RevalidateMaxFailures = 3
	})
	api.revalidateStatusFn = func(int64) int { return http.StatusInternalServerError }
	c := connect(t, ts, "tok")
	if got := c.awaitClose(t, 3*time.Second); got != closeMaintenance {
		t.Fatalf("close code = %d, want 1001 after consecutive revalidation failures", got)
	}
	waitEndCount(t, api, 1, 2*time.Second)
	if api.sessionEnds[0].Reason != EndRevalidationDenied {
		t.Fatalf("end reason = %q, want REVALIDATION_DENIED", api.sessionEnds[0].Reason)
	}
	if api.revalidateCalls.Load() < 3 {
		t.Fatalf("expected >=3 revalidation attempts before close, got %d", api.revalidateCalls.Load())
	}
}

// A success between failures resets the counter, so a fail/fail/success pattern
// (never MaxFailures consecutive) keeps the session alive.
func TestBridge_RevalidateFailureCounterResets(t *testing.T) {
	_, api, _, ts := testBridge(t, fakeVMOpts{}, func(c *Config) {
		c.RevalidateInterval = 40 * time.Millisecond
		c.RevalidateMaxFailures = 3
	})
	// Every 3rd poll succeeds → at most 2 consecutive failures, below the cap.
	api.revalidateStatusFn = func(n int64) int {
		if n%3 == 0 {
			return http.StatusOK
		}
		return http.StatusInternalServerError
	}
	c := connect(t, ts, "tok")
	time.Sleep(500 * time.Millisecond) // ~12 polls
	select {
	case code := <-c.closeCode:
		t.Fatalf("session closed early (%d) — counter should reset on each success", code)
	default:
	}
	if api.revalidateCalls.Load() < 6 {
		t.Fatalf("expected the session to keep polling (>=6), got %d", api.revalidateCalls.Load())
	}
	_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
}

// A redeem-200 with an empty hostKeys array is a host-key/connection failure →
// close 4006 (not the 1001 maintenance bucket).
func TestBridge_RedeemEmptyHostKeysClosesConnFailed(t *testing.T) {
	_, api, _, ts := testBridge(t, fakeVMOpts{}, nil)
	api.redeemResult.HostKeys = nil // 200 but no host keys
	c := connect(t, ts, "tok")
	if got := c.awaitClose(t, 3*time.Second); got != closeConnFailed {
		t.Fatalf("close code = %d, want 4006 for empty hostKeys", got)
	}
	if len(api.sessionStarts) != 0 {
		t.Fatalf("empty hostKeys must not start a session: %+v", api.sessionStarts)
	}
}

func TestBridge_RevalidateSessionUnknownClosesMaintenance(t *testing.T) {
	_, api, _, ts := testBridge(t, fakeVMOpts{}, func(c *Config) {
		c.RevalidateInterval = 120 * time.Millisecond
	})
	api.revalidateFn = func(int64) (bool, string) { return false, reasonSessionUnknown }
	c := connect(t, ts, "tok")
	if got := c.awaitClose(t, 3*time.Second); got != closeMaintenance {
		t.Fatalf("close code = %d, want 1001 for SESSION_UNKNOWN", got)
	}
	waitEndCount(t, api, 1, 2*time.Second)
}

func TestBridge_ControlTerminate(t *testing.T) {
	b, api, _, ts := testBridge(t, fakeVMOpts{}, nil)
	c := connect(t, ts, "tok")
	_ = c.send([]byte("hi\n"))
	c.awaitBinaryContains(t, "hi", 3*time.Second)

	// Force-terminate via the control handler (as pickle-api would).
	req := httptest.NewRequest(http.MethodPost, "/control/terminate",
		strings.NewReader(`{"sessionId":"sess-1"}`))
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("Authorization", "Bearer ctok")
	rec := httptest.NewRecorder()
	b.ControlHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("control terminate = %d, want 204", rec.Code)
	}

	if got := c.awaitClose(t, 3*time.Second); got != closeForce {
		t.Fatalf("close code = %d, want 4002", got)
	}
	waitEndCount(t, api, 1, 2*time.Second)
	if api.sessionEnds[0].Reason != EndForceTerminated {
		t.Fatalf("end reason = %q, want FORCE_TERMINATED", api.sessionEnds[0].Reason)
	}
}

func TestBridge_ServerInitiatedChannelRejected(t *testing.T) {
	_, api, vm, ts := testBridge(t, fakeVMOpts{attemptServerChannel: true}, nil)
	c := connect(t, ts, "tok")
	_ = c.send([]byte("hi\n"))
	c.awaitBinaryContains(t, "hi", 3*time.Second)

	select {
	case err := <-vm.serverChanCh:
		if err == nil {
			t.Fatal("server-initiated channel must be rejected by the bridge's ssh.Client")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("VM never got a result for its server-initiated channel open")
	}
	_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
	waitEndCount(t, api, 1, 3*time.Second)
}

func TestBridge_SessionStartConflictCloses(t *testing.T) {
	_, api, _, ts := testBridge(t, fakeVMOpts{}, nil)
	api.sessionStartStatus = http.StatusConflict
	c := connect(t, ts, "tok")
	if got := c.awaitClose(t, 3*time.Second); got != closeMaintenance {
		t.Fatalf("close code = %d, want 1001 on session-start 409", got)
	}
}

func TestBridge_Shutdown(t *testing.T) {
	b, api, _, ts := testBridge(t, fakeVMOpts{}, nil)
	c := connect(t, ts, "tok")
	_ = c.send([]byte("hi\n"))
	c.awaitBinaryContains(t, "hi", 3*time.Second)

	b.Shutdown()
	if got := c.awaitClose(t, 3*time.Second); got != closeMaintenance {
		t.Fatalf("close code = %d, want 1001 on shutdown", got)
	}
	waitEndCount(t, api, 1, 2*time.Second)
	if api.sessionEnds[0].Reason != EndBridgeShutdown {
		t.Fatalf("end reason = %q, want BRIDGE_SHUTDOWN", api.sessionEnds[0].Reason)
	}
}
