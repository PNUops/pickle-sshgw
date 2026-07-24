// Package proxyfront is the PROXY-protocol-required ingress shim that fronts
// sshpiperd on the Pickle SSH gateway.
//
// Why it exists: the internal route contract's "PROXY protocol trust
// conditions" require the :22 listener to run in PROXY-REQUIRED
// mode — a connection that does not open with a valid PROXY protocol v2 header
// from the WireGuard peer is dropped with no SSH bytes exchanged, and there is
// no fallback to trusting the raw TCP source. sshpiperd's built-in PROXY support
// (--allowed-proxy-addresses) only offers the deprecated *lax* policy (header
// optional for the peer), which would serve a headerless connection raw. This
// shim closes that gap: it terminates PROXY with go-proxyproto's REQUIRE policy
// (TrustProxyHeaderFromRanges) restricted to the peer, then re-emits a fresh
// PROXY v2 header carrying the recovered real client IP to loopback sshpiperd
// (which runs with --allowed-proxy-addresses 127.0.0.1/32 and recovers that IP
// for the routing plugin). Bytes are then spliced 1:1.
package proxyfront

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	log "github.com/sirupsen/logrus"
)

// DefaultReadHeaderTimeout bounds how long a single connection may take to send
// its PROXY header before it is dropped.
const DefaultReadHeaderTimeout = 5 * time.Second

// Config configures the shim.
type Config struct {
	// Listen is the ingress address, bound to the WireGuard interface address
	// (e.g. "10.100.100.2:22") so the listener is unreachable unless the tunnel
	// is up (fail-closed) — nftables enforces peer-only as defence in depth.
	Listen string
	// Upstream is the loopback sshpiperd address (e.g. "127.0.0.1:2222").
	Upstream string
	// TrustedRanges are the source ranges permitted to send a PROXY header
	// (the WireGuard peer, e.g. []string{"10.100.100.1/32"}). Any other source
	// is dropped by Accept; these sources MUST send a valid header (REQUIRE).
	TrustedRanges []string
	// ReadHeaderTimeout bounds PROXY header reads. Zero uses the default.
	ReadHeaderTimeout time.Duration
	// DialTimeout bounds the dial to the upstream. Zero uses 5s.
	DialTimeout time.Duration
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Listen) == "" {
		return fmt.Errorf("proxyfront: Listen is required")
	}
	if strings.TrimSpace(c.Upstream) == "" {
		return fmt.Errorf("proxyfront: Upstream is required")
	}
	if len(c.TrustedRanges) == 0 {
		return fmt.Errorf("proxyfront: at least one TrustedRange is required (fail-closed)")
	}
	return nil
}

// Server is a running shim.
type Server struct {
	cfg      Config
	ln       net.Listener
	dialTO   time.Duration
	wg       sync.WaitGroup
	closeOne sync.Once
}

// Listen builds the REQUIRE/peer-only PROXY listener but does not accept yet.
func Listen(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// REQUIRE for trusted peers, REJECT for everything else: a trusted source
	// MUST send a valid header, and no source is ever served raw.
	policy, err := proxyproto.TrustProxyHeaderFromRanges(cfg.TrustedRanges)
	if err != nil {
		return nil, fmt.Errorf("proxyfront: bad TrustedRanges: %w", err)
	}
	raw, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("proxyfront: listen %s: %w", cfg.Listen, err)
	}
	rht := cfg.ReadHeaderTimeout
	if rht <= 0 {
		rht = DefaultReadHeaderTimeout
	}
	dto := cfg.DialTimeout
	if dto <= 0 {
		dto = 5 * time.Second
	}
	return &Server{
		cfg: cfg,
		ln: &proxyproto.Listener{
			Listener:          raw,
			ConnPolicy:        policy,
			ReadHeaderTimeout: rht,
		},
		dialTO: dto,
	}, nil
}

// Addr is the bound listen address (useful in tests with :0).
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Serve accepts and handles connections until the listener is closed.
func (s *Server) Serve() error {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			// A closed listener ends Serve cleanly; anything else is logged and
			// the loop continues (a single bad connection must not kill the gw).
			if errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			log.WithField("err", err.Error()).Warn("proxyfront accept error")
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

// Close stops accepting and waits for in-flight connections to drain.
func (s *Server) Close() error {
	var err error
	s.closeOne.Do(func() { err = s.ln.Close() })
	return err
}

// handle validates the PROXY header, re-emits it to the upstream, and splices.
func (s *Server) handle(c net.Conn) {
	defer c.Close()

	pc, ok := c.(*proxyproto.Conn)
	if !ok {
		// Should not happen: a REQUIRE policy never returns a raw conn (SKIP is
		// not configured). Refuse rather than serve an unvalidated connection.
		log.WithField("remote", c.RemoteAddr().String()).
			Warn("proxyfront dropped: connection was not PROXY-wrapped")
		return
	}

	// ProxyHeader triggers header processing; it returns nil on any error
	// (absent or malformed). Under REQUIRE a valid header is mandatory, so nil
	// here means "drop with no SSH bytes exchanged" — contract condition #1/#3.
	hdr := pc.ProxyHeader()
	if hdr == nil || hdr.Command.IsLocal() || hdr.SourceAddr == nil {
		log.WithField("peer", c.RemoteAddr().String()).
			Warn("proxyfront dropped: absent/invalid PROXY header")
		return
	}

	up, err := net.DialTimeout("tcp", s.cfg.Upstream, s.dialTO)
	if err != nil {
		log.WithFields(log.Fields{"upstream": s.cfg.Upstream, "err": err.Error()}).
			Error("proxyfront dropped: upstream dial failed")
		return
	}
	defer up.Close()

	// Re-emit a fresh PROXY v2 header carrying the recovered real client
	// address so loopback sshpiperd sees the client IP, not the shim.
	out := proxyproto.HeaderProxyFromAddrs(2, hdr.SourceAddr, hdr.DestinationAddr)
	if _, err := out.WriteTo(up); err != nil {
		log.WithField("err", err.Error()).Warn("proxyfront: write PROXY header to upstream failed")
		return
	}

	splice(pc, up)
}

// splice copies bytes both ways until either side closes, then tears both down.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
