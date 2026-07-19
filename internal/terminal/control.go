package terminal

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// ControlHandler serves Link 3b (docs/api/internal.md): pickle-api → bridge
// force-terminate at POST /control/terminate. It authenticates the caller by
// bearer token (constant-time) and source IP, then closes the named session with
// 4002 (FORCE_TERMINATED) if live, or no-ops. It always answers 204 (idempotent).
func (b *Bridge) ControlHandler() http.Handler {
	return http.HandlerFunc(b.handleControl)
}

func (b *Bridge) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/control/terminate" {
		http.NotFound(w, r)
		return
	}
	// Source IP: only pickle-api (LXC 101) may reach the control port. nftables
	// enforces this too; the code checks in depth.
	if peerIP := hostFromAddr(r.RemoteAddr); peerIP != b.cfg.ControlAllowedSourceIP {
		log.WithField("peer", peerIP).Warn("terminal control rejected: source IP not allowed")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Bearer token, constant-time compared. Fail-closed on a missing/short header.
	if !bearerEquals(r.Header.Get("Authorization"), b.cfg.ControlToken) {
		log.Warn("terminal control rejected: bad token")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		SessionID string `json:"sessionId"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err := json.Unmarshal(raw, &req); err != nil || req.SessionID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if s, ok := b.lookup(req.SessionID); ok {
		log.WithField("sessionId", req.SessionID).Info("terminal force-terminate")
		s.end(EndForceTerminated, closeForce)
	}
	// Idempotent: unknown/already-closed sessionId is a 204 no-op.
	w.WriteHeader(http.StatusNoContent)
}

// bearerEquals reports whether the Authorization header carries exactly
// "Bearer <want>", compared in constant time. An empty want (misconfiguration)
// never matches.
func bearerEquals(header, want string) bool {
	const prefix = "Bearer "
	if want == "" || len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return false
	}
	got := header[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
