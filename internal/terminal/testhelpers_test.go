package terminal

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- fake VM (embedded SSH server) -----------------------------------------

// fakeVMOpts tunes the embedded SSH server.
type fakeVMOpts struct {
	// attemptServerChannel makes the server open a channel back to the client
	// once a session is established (to prove the bridge's ssh.Client rejects
	// all server-initiated channels).
	attemptServerChannel bool
}

// fakeVM is an in-process SSH server standing in for a user VM: it authenticates
// any public key, serves a single session channel with pty+shell, echoes stdin to
// stdout, and records window-change (resize) requests.
type fakeVM struct {
	ln          net.Listener
	addr        string
	hostKeyLine string // authorized_keys-format line of the host key
	signer      ssh.Signer

	resizeCh     chan [2]int // {cols, rows}
	serverChanCh chan error  // result of a server-initiated channel open (if attempted)
	opts         fakeVMOpts
}

func startFakeVM(t *testing.T, opts fakeVMOpts) *fakeVM {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	vm := &fakeVM{
		ln:           ln,
		addr:         ln.Addr().String(),
		hostKeyLine:  string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		signer:       signer,
		resizeCh:     make(chan [2]int, 8),
		serverChanCh: make(chan error, 1),
		opts:         opts,
	}
	t.Cleanup(func() { _ = ln.Close() })
	go vm.serve()
	return vm
}

func (vm *fakeVM) serve() {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(vm.signer)
	for {
		nConn, err := vm.ln.Accept()
		if err != nil {
			return
		}
		go vm.handleConn(nConn, cfg)
	}
}

func (vm *fakeVM) handleConn(nConn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		_ = nConn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	if vm.opts.attemptServerChannel {
		go func() {
			// The bridge builds its client with ssh.NewClient and registers no
			// channel handlers, so this must be rejected.
			_, _, err := sconn.OpenChannel("forbidden@pickle", nil)
			vm.serverChanCh <- err
		}()
	}

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go vm.handleSession(ch, chReqs)
	}
}

func (vm *fakeVM) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "window-change":
			var m struct{ Columns, Rows, Width, Height uint32 }
			if err := ssh.Unmarshal(req.Payload, &m); err == nil {
				select {
				case vm.resizeCh <- [2]int{int(m.Columns), int(m.Rows)}:
				default:
				}
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			// Echo stdin back to stdout until the channel closes.
			go func() {
				_, _ = io.Copy(ch, ch)
				_ = ch.Close()
			}()
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// --- fake pickle-api (internal terminal endpoints) -------------------------

// fakeAPI is a configurable stand-in for pickle-api's /internal/terminal/*
// endpoints. All behaviour knobs are set before use; captures are read after.
type fakeAPI struct {
	srv *httptest.Server

	// knobs
	redeemReason         string       // if set, redeem returns 403 {reason}
	redeemResult         RedeemResult // returned on 200 (SessionID/Port/User/HostKeys filled by caller)
	redeemStatusOverride int          // if non-zero, return this raw status (transport-error simulation)
	sessionStartStatus   int          // default 204
	revalidateFn         func(n int64) (allow bool, reason string)
	revalidateStatusFn   func(n int64) int // if it returns non-0/non-200, that raw status is sent (transport-error sim)
	sessionEndDelay      time.Duration     // artificial delay before responding to session-end (slow-api sim)

	// captures
	mu              sync.Mutex
	gotAuth         string
	sessionStarts   []struct{ SessionID, ClientIP string }
	sessionEnds     []SessionEndRequest
	revalidateCalls atomic.Int64
	redeemCalls     atomic.Int64
}

func startFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	a := &fakeAPI{sessionStartStatus: http.StatusNoContent}
	a.srv = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAPI) baseURL() string { return a.srv.URL }

func (a *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.gotAuth = r.Header.Get("Authorization")
	a.mu.Unlock()

	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	switch r.URL.Path {
	case "/internal/terminal/redeem":
		a.redeemCalls.Add(1)
		if a.redeemStatusOverride != 0 {
			w.WriteHeader(a.redeemStatusOverride)
			return
		}
		if a.redeemReason != "" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"reason": a.redeemReason})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(a.redeemResult)
	case "/internal/terminal/session-start":
		var body struct{ SessionID, ClientIP string }
		_ = json.Unmarshal(raw, &body)
		a.mu.Lock()
		a.sessionStarts = append(a.sessionStarts, struct{ SessionID, ClientIP string }{body.SessionID, body.ClientIP})
		a.mu.Unlock()
		w.WriteHeader(a.sessionStartStatus)
	case "/internal/terminal/session-end":
		if a.sessionEndDelay > 0 {
			time.Sleep(a.sessionEndDelay) // simulate a slow api session-end
		}
		var body SessionEndRequest
		_ = json.Unmarshal(raw, &body)
		a.mu.Lock()
		a.sessionEnds = append(a.sessionEnds, body)
		a.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "/internal/terminal/revalidate":
		n := a.revalidateCalls.Add(1)
		if a.revalidateStatusFn != nil {
			if st := a.revalidateStatusFn(n); st != 0 && st != http.StatusOK {
				w.WriteHeader(st) // simulate an api transport/5xx error
				return
			}
		}
		allow, reason := true, ""
		if a.revalidateFn != nil {
			allow, reason = a.revalidateFn(n)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"allow": allow, "reason": reason})
	default:
		http.NotFound(w, r)
	}
}

func (a *fakeAPI) endReasons() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.sessionEnds))
	for _, e := range a.sessionEnds {
		out = append(out, e.Reason)
	}
	return out
}

func (a *fakeAPI) endCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sessionEnds)
}

// newTestSigner builds an ed25519 signer for the bridge's terminal key in tests.
func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}
