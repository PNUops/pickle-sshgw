package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// Bridge terminates browser WebSockets and relays them to VMs over locked-down
// SSH. It owns the live sessions (the api registry is a reported mirror). It is
// constructed with a resolved terminal signer and api client so it is testable
// without touching the filesystem.
type Bridge struct {
	cfg    Config
	signer ssh.Signer
	api    *APIClient

	mu       sync.Mutex
	sessions map[string]*session
	active   int // reserved+registered slot count, for the global hard cap
	closed   bool
}

// NewBridge builds a Bridge. cfg must already be validated.
func NewBridge(cfg Config, signer ssh.Signer, api *APIClient) *Bridge {
	return &Bridge{
		cfg:      cfg,
		signer:   signer,
		api:      api,
		sessions: make(map[string]*session),
	}
}

// WSHandler serves the browser WS ingress at /terminal/ws.
func (b *Bridge) WSHandler() http.Handler {
	return http.HandlerFunc(b.handleWS)
}

// handleWS runs the handshake (source IP, Origin, subprotocol/ticket, redeem)
// and, on success, the SSH dial + relay. The offered subprotocol strings are
// never logged (they carry the ticket).
func (b *Bridge) handleWS(w http.ResponseWriter, r *http.Request) {
	// ① source IP: only the LXC 100 nginx TLS tier may reach the WS ingress.
	peerIP := hostFromAddr(r.RemoteAddr)
	if peerIP != b.cfg.WSAllowedSourceIP {
		log.WithField("peer", peerIP).Warn("terminal WS rejected: source IP not allowed")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// ② Origin must exactly equal the console origin. Rejecting at the HTTP layer
	// (before the WS upgrade) so the browser sees a plain 403.
	if origin := r.Header.Get("Origin"); origin != b.cfg.ConsoleOrigin {
		log.Warn("terminal WS rejected: Origin mismatch")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// ③ subprotocol: exactly [pickle.terminal.v1, ticket.<t>]. Parse the ticket
	// without logging the offered strings.
	ticket, ok := parseSubprotocols(r.Header.Values("Sec-WebSocket-Protocol"))
	if !ok {
		log.Warn("terminal WS rejected: malformed subprotocol set")
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// ④ client IP is what the TLS tier passed as X-Real-IP (CF-range-validated).
	clientIP := r.Header.Get("X-Real-IP")

	// Accept, echoing ONLY the fixed subprotocol name (never the ticket element).
	// Origin was already checked above, so skip the library's origin check.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{Subprotocol},
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.WithField("err", err.Error()).Warn("terminal WS accept failed")
		return
	}
	// Raise the client→bridge read limit above coder's 32KiB default so a large
	// paste (e.g. into vim) does not error the read and kill the session.
	conn.SetReadLimit(b.cfg.MaxFrameBytes)

	// ⑤ redeem the ticket. On a deny, accept-then-close with the mapped code (the
	// browser cannot read a close code from a rejected *handshake*, so we accept
	// first and close with the reason). On a transport/unexpected error, close
	// 1001 (server-side condition, reconnect prompt).
	ctx, cancel := context.WithTimeout(r.Context(), b.cfg.APITimeout)
	res, err := b.api.Redeem(ctx, ticket)
	cancel()
	if err != nil {
		var d *Denial
		if errors.As(err, &d) {
			code := closeCodeForReason(d.Reason)
			log.WithField("reason", d.Reason).Info("terminal redeem denied")
			closeWith(conn, code)
			return
		}
		if errors.Is(err, ErrNoHostKeys) {
			// Host-key problem, not a maintenance condition → 4006.
			log.WithField("err", err.Error()).Warn("terminal redeem returned no host keys (fail-closed)")
			closeWith(conn, closeConnFailed)
			return
		}
		log.WithField("err", err.Error()).Warn("terminal redeem failed (fail-closed)")
		closeWith(conn, closeMaintenance)
		return
	}

	b.serveSession(conn, res, clientIP)
}

// serveSession dials the VM, reports session-start, and runs the relay until the
// session ends. All teardown flows through session.end exactly once.
func (b *Bridge) serveSession(conn *websocket.Conn, res *RedeemResult, clientIP string) {
	// Global hard cap (defence in depth on top of the api caps). Reserve a slot
	// before any SSH dial or session-start so a rejected session is never
	// reported/registered — accept-then-close 4006.
	if !b.acquire() {
		log.WithField("sessionId", res.SessionID).Warn("terminal at session capacity, rejecting (4006)")
		closeWith(conn, closeConnFailed)
		return
	}
	s := &session{
		id:        res.SessionID,
		conn:      conn,
		api:       b.api,
		cfg:       &b.cfg,
		bridge:    b,
		startedAt: time.Now(),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())

	// SSH dial (host-key pinned, channel-locked-down). A failure closes 4006 and
	// reports session-end SSH_FAILED (the session may fail SSH-side without ever
	// starting — the api mirror simply no-ops the unknown session).
	client, err := DialVM(s.ctx, DialParams{
		Addr:     net.JoinHostPort(res.VMIp, strconv.Itoa(res.Port)),
		User:     res.User,
		HostKeys: res.HostKeys,
		Signer:   b.signer,
		Timeout:  b.cfg.SSHConnectTimeout,
	})
	if err != nil {
		log.WithFields(log.Fields{"sessionId": s.id, "err": err.Error()}).
			Warn("terminal SSH dial failed (fail-closed)")
		s.end(EndSSHFailed, closeConnFailed)
		return
	}
	s.sshClient = client

	sess, err := client.NewSession()
	if err != nil {
		log.WithFields(log.Fields{"sessionId": s.id, "err": err.Error()}).
			Warn("terminal SSH open session failed")
		s.end(EndSSHFailed, closeConnFailed)
		return
	}
	s.sshSession = sess

	// Wire SSH stdout/stderr to the WS as binary frames (counted, never logged).
	out := &wsBinaryWriter{s: s}
	sess.Stdout = out
	sess.Stderr = out
	stdin, err := sess.StdinPipe()
	if err != nil {
		s.end(EndSSHFailed, closeConnFailed)
		return
	}
	s.stdin = stdin

	modes := ssh.TerminalModes{ssh.ECHO: 1}
	if err := sess.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		log.WithFields(log.Fields{"sessionId": s.id, "err": err.Error()}).
			Warn("terminal pty request failed")
		s.end(EndSSHFailed, closeConnFailed)
		return
	}
	if err := sess.Shell(); err != nil {
		log.WithFields(log.Fields{"sessionId": s.id, "err": err.Error()}).
			Warn("terminal shell request failed")
		s.end(EndSSHFailed, closeConnFailed)
		return
	}

	// Report session-start; a 409 means the api considers the session gone —
	// close as an inconsistent state (1001).
	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.APITimeout)
	err = b.api.SessionStart(ctx, s.id, clientIP)
	cancel()
	if err != nil {
		if errors.Is(err, ErrSessionConflict) {
			log.WithField("sessionId", s.id).Warn("terminal session-start 409 (inconsistent), closing")
			s.end(EndRevalidationDenied, closeMaintenance)
			return
		}
		// A transport failure on session-start is fail-closed: without the audit
		// registration the session must not proceed.
		log.WithFields(log.Fields{"sessionId": s.id, "err": err.Error()}).
			Warn("terminal session-start failed (fail-closed)")
		s.end(EndSSHFailed, closeConnFailed)
		return
	}

	b.register(s)
	log.WithFields(log.Fields{"sessionId": s.id}).Info("terminal session started")

	// Background loops: idle timer, server ping, revalidation poll, SSH wait.
	s.idleTimer = time.AfterFunc(b.cfg.IdleTimeout, func() {
		log.WithField("sessionId", s.id).Info("terminal idle timeout")
		s.end(EndIdleTimeout, closeIdle)
	})
	go s.pingLoop()
	go s.revalidateLoop()
	go func() {
		// When the shell exits (user typed exit, or SSH dropped), end normally.
		_ = sess.Wait()
		s.end(EndClientClosed, closeNormal)
	}()

	// Foreground: WS read loop (client input + control frames). Returns when the
	// connection closes; end() is idempotent so a concurrent cause wins the reason.
	s.readLoop()
	s.end(EndClientClosed, closeNormal)
}

// acquire reserves a session slot under the global cap. It returns false when the
// bridge is at capacity or shutting down. Every successful acquire is balanced by
// exactly one release (called from session.end).
func (b *Bridge) acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.active >= b.cfg.MaxSessions {
		return false
	}
	b.active++
	return true
}

// release returns a previously acquired slot.
func (b *Bridge) release() {
	b.mu.Lock()
	if b.active > 0 {
		b.active--
	}
	b.mu.Unlock()
}

func (b *Bridge) register(s *session) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sessions[s.id] = s
}

func (b *Bridge) unregister(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, id)
}

func (b *Bridge) lookup(id string) (*session, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[id]
	return s, ok
}

// Shutdown closes every live session with 1001 and reports BRIDGE_SHUTDOWN, for a
// graceful SIGTERM (deploy pair-swap). It is safe to call once.
func (b *Bridge) Shutdown() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	live := make([]*session, 0, len(b.sessions))
	for _, s := range b.sessions {
		live = append(live, s)
	}
	b.mu.Unlock()

	var wg sync.WaitGroup
	for _, s := range live {
		wg.Add(1)
		go func(s *session) {
			defer wg.Done()
			s.end(EndBridgeShutdown, closeMaintenance)
		}(s)
	}
	wg.Wait()
}

// session is one live WS+SSH relay.
type session struct {
	id     string
	conn   *websocket.Conn
	api    *APIClient
	cfg    *Config
	bridge *Bridge

	writeMu    sync.Mutex
	sshClient  *ssh.Client
	sshSession *ssh.Session
	stdin      io.WriteCloser

	bytesIn   atomic.Int64
	bytesOut  atomic.Int64
	startedAt time.Time
	idleTimer *time.Timer

	ctx     context.Context
	cancel  context.CancelFunc
	endOnce sync.Once
}

// readLoop reads client frames until the connection closes. Binary frames are
// client input (counted, reset the idle timer, written to SSH stdin). Text frames
// are JSON control (resize). It uses a background context: the connection is
// unblocked by conn.Close in end(), not by cancelling this read.
func (s *session) readLoop() {
	for {
		typ, data, err := s.conn.Read(context.Background())
		if err != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			s.bytesIn.Add(int64(len(data)))
			if s.idleTimer != nil {
				s.idleTimer.Reset(s.cfg.IdleTimeout)
			}
			if _, werr := s.stdin.Write(data); werr != nil {
				s.end(EndSSHFailed, closeConnFailed)
				return
			}
		case websocket.MessageText:
			s.handleControl(data)
		}
	}
}

// controlMessage is the client→server JSON control frame. Only "resize" is used.
type controlMessage struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// handleControl applies a resize control frame (window-change). Resize does NOT
// reset the idle timer (only client input does). Malformed control frames are
// ignored (never logged with content).
func (s *session) handleControl(data []byte) {
	var msg controlMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	if msg.Type == "resize" && msg.Cols > 0 && msg.Rows > 0 && s.sshSession != nil {
		_ = s.sshSession.WindowChange(msg.Rows, msg.Cols)
	}
}

// pingLoop sends a server WS ping on the configured cadence to keep the
// connection warm (CF ~100s idle). A failed ping means the connection is dead —
// end the session.
func (s *session) pingLoop() {
	t := time.NewTicker(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(s.ctx, s.cfg.WSWriteTimeout)
			err := s.conn.Ping(ctx)
			cancel()
			if err != nil {
				s.end(EndClientClosed, closeNormal)
				return
			}
		}
	}
}

// revalidateLoop polls the api every RevalidateInterval. An explicit deny closes
// the session at once (reason mapped to a close code, reported as
// REVALIDATION_DENIED). A transport error is fail-open — a single missed poll must
// not kill a live session during an api blip — but only up to
// RevalidateMaxFailures *consecutive* errors: past that the session is closed
// 1001, so a prolonged api outage cannot leave a session immune to the kill
// switch / membership revocation / admin force-terminate (all api-mediated). A
// successful poll resets the counter.
func (s *session) revalidateLoop() {
	t := time.NewTicker(s.cfg.RevalidateInterval)
	defer t.Stop()
	failures := 0
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(s.ctx, s.cfg.APITimeout)
			err := s.api.Revalidate(ctx, s.id)
			cancel()
			if err == nil {
				failures = 0
				continue
			}
			var d *Denial
			if errors.As(err, &d) {
				log.WithFields(log.Fields{"sessionId": s.id, "reason": d.Reason}).
					Info("terminal revalidation denied")
				s.end(EndRevalidationDenied, closeCodeForReason(d.Reason))
				return
			}
			failures++
			if failures >= s.cfg.RevalidateMaxFailures {
				log.WithFields(log.Fields{"sessionId": s.id, "failures": failures, "err": err.Error()}).
					Warn("terminal revalidation failed too many times consecutively (closing)")
				s.end(EndRevalidationDenied, closeMaintenance)
				return
			}
			// Transport error under the cap: log and keep the session (fail-open).
			log.WithFields(log.Fields{"sessionId": s.id, "failures": failures, "err": err.Error()}).
				Warn("terminal revalidation poll failed (kept alive)")
		}
	}
}

// end tears the session down exactly once: send the Korean exit control frame,
// close the WS with the code, close SSH, and report session-end (idempotent api
// side, so retry-safe). The first caller's reason/code wins.
func (s *session) end(reason string, code websocket.StatusCode) {
	s.endOnce.Do(func() {
		if s.idleTimer != nil {
			s.idleTimer.Stop()
		}
		s.sendExit(code)
		_ = s.conn.Close(code, closeReason(code))
		s.cancel()
		if s.sshSession != nil {
			_ = s.sshSession.Close()
		}
		if s.sshClient != nil {
			_ = s.sshClient.Close()
		}
		if s.bridge != nil {
			s.bridge.unregister(s.id)
			s.bridge.release() // balance the acquire from serveSession
		}

		dur := int64(time.Since(s.startedAt).Seconds())
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.APITimeout)
		defer cancel()
		if err := s.api.SessionEnd(ctx, SessionEndRequest{
			SessionID:       s.id,
			Reason:          reason,
			DurationSeconds: dur,
			BytesIn:         s.bytesIn.Load(),
			BytesOut:        s.bytesOut.Load(),
		}); err != nil {
			log.WithFields(log.Fields{"sessionId": s.id, "reason": reason, "err": err.Error()}).
				Warn("terminal session-end report failed (session already torn down)")
		}
		log.WithFields(log.Fields{
			"sessionId": s.id, "reason": reason, "closeCode": int(code),
			"durationSeconds": dur, "bytesIn": s.bytesIn.Load(), "bytesOut": s.bytesOut.Load(),
		}).Info("terminal session ended")
	})
}

// exitFrame is the server→client JSON control frame sent just before close.
type exitFrame struct {
	Type    string `json:"type"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// sendExit writes the exit control frame (best-effort, short timeout).
func (s *session) sendExit(code websocket.StatusCode) {
	frame, err := json.Marshal(exitFrame{Type: "exit", Code: int(code), Message: closeMessage(code)})
	if err != nil {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.WSWriteTimeout)
	defer cancel()
	_ = s.conn.Write(ctx, websocket.MessageText, frame)
}

// wsBinaryWriter frames SSH output to the WS as binary and counts bytes. On a WS
// write error (slow/dead client) it ends the session 4006 and returns the error,
// which stops the ssh copy loop.
type wsBinaryWriter struct{ s *session }

func (w *wsBinaryWriter) Write(p []byte) (int, error) {
	w.s.writeMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), w.s.cfg.WSWriteTimeout)
	err := w.s.conn.Write(ctx, websocket.MessageBinary, p)
	cancel()
	w.s.writeMu.Unlock()
	if err != nil {
		go w.s.end(EndSSHFailed, closeConnFailed)
		return 0, err
	}
	w.s.bytesOut.Add(int64(len(p)))
	return len(p), nil
}

// closeWith sends the exit control frame and closes a WS that has no session yet
// (a redeem deny before any SSH). It never reports session-end (the session never
// started — the api defers auditing to session-start).
func closeWith(conn *websocket.Conn, code websocket.StatusCode) {
	frame, err := json.Marshal(exitFrame{Type: "exit", Code: int(code), Message: closeMessage(code)})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultWSWriteTimeout)
		_ = conn.Write(ctx, websocket.MessageText, frame)
		cancel()
	}
	_ = conn.Close(code, closeReason(code))
}

// hostFromAddr strips the port from a "host:port" RemoteAddr, tolerating a bare
// host.
func hostFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
