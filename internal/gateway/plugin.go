// Package gateway wires the route-resolution client into sshpiperd plugin
// callbacks. On every incoming SSH connection sshpiperd invokes the plugin per
// auth attempt: PublicKeyCallback with the offered key, or PasswordCallback
// with the typed password. The callback asks pickle-api (route API v2) where to
// route and how to authorize, and pipes the session to the user's VM. On the
// publickey path the gateway re-authenticates upstream with its own platform
// key and identifies the person by key fingerprint; on the password path it
// passes the typed password through (per-VM opt-in, enforced by the API). Both
// paths pin the VM's host key, verified by VerifyHostKeyCallback. Every failure
// refuses the session — the plugin is fail-closed throughout.
package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pickle/sshgw/internal/route"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

// Resolver resolves a route request to an upstream route and emits the
// authenticated-session audit. *route.Client implements it; tests substitute a
// fake.
type Resolver interface {
	Resolve(ctx context.Context, req route.Request) (*route.Route, error)
	SessionStart(ctx context.Context, req route.Request) error
}

// sessionAuditTimeout bounds the fire-and-forget PipeStart session-audit call so
// a slow/hung pickle-api can never accumulate goroutines. The session is already
// live and is never gated on this call.
const sessionAuditTimeout = 3 * time.Second

// Plugin holds the callback dependencies.
type Plugin struct {
	resolver    Resolver
	platformKey []byte // validated PEM of the upstream platform private key
	store       *connStore
}

// New builds a Plugin from a resolver and the platform upstream private key
// (PEM, already validated by LoadUpstreamKey).
func New(resolver Resolver, platformKey []byte) *Plugin {
	return &Plugin{
		resolver:    resolver,
		platformKey: platformKey,
		store:       newConnStore(defaultMemoTTL),
	}
}

// Config returns the sshpiperd plugin config. It wires the three auth-time
// callbacks — public key (the default identity path), password (per-VM opt-in
// passthrough), and upstream host-key verification (pins the VM's collected host
// key) — plus PipeStart, which fires once per established session and emits the
// authenticated per-user audit (G6).
func (p *Plugin) Config() *libplugin.SshPiperPluginConfig {
	return &libplugin.SshPiperPluginConfig{
		PublicKeyCallback:     p.publicKeyCallback,
		PasswordCallback:      p.passwordCallback,
		VerifyHostKeyCallback: p.verifyHostKeyCallback,
		PipeStartCallback:     p.pipeStartCallback,
	}
}

// publicKeyCallback is the per-user identity path. sshpiperd has already
// verified the downstream signature, so the offered key proves possession; the
// plugin only needs to identify it. It parses the wire key (rejecting malformed
// input), computes its OpenSSH SHA-256 fingerprint, and asks the route API
// whether that key's owner may reach this VM. The (connection, fingerprint) →
// result is memoized for the auth window so re-offers of the same key cost one
// API call. On success it pins the VM's host keys and pipes the session,
// authenticating upstream with the platform key. Fail-closed: any error returns
// a nil upstream.
func (p *Plugin) publicKeyCallback(conn libplugin.ConnMetadata, keyBlob []byte) (*libplugin.Upstream, error) {
	slug := conn.User()
	sourceIP := hostFromAddr(conn.RemoteAddr())
	connID := conn.UniqueID()

	pub, err := ssh.ParsePublicKey(keyBlob)
	if err != nil {
		log.WithFields(log.Fields{
			"slug": slug, "sourceIp": sourceIP, "authMethod": route.AuthPublicKey,
			"err": err.Error(),
		}).Error("sshgw offered public key unparseable (fail-closed)")
		return nil, fmt.Errorf("gateway: parse offered public key: %w", err)
	}
	fingerprint := ssh.FingerprintSHA256(pub)

	r, err := p.resolveMemoized(connID, route.Request{
		Slug: slug, SourceIP: sourceIP, AuthMethod: route.AuthPublicKey,
		PublicKeyFingerprint: fingerprint, ConnectionID: connID,
	})
	base := log.Fields{
		"slug": slug, "sourceIp": sourceIP,
		"authMethod": route.AuthPublicKey, "fingerprint": fingerprint,
	}
	if err != nil {
		logResolveErr(base, err)
		return nil, err
	}
	if r == nil {
		// A well-behaved resolver never returns (nil, nil); guard anyway so a
		// future resolver contract slip refuses the session rather than panics.
		return nil, fmt.Errorf("gateway: resolver returned no route and no error (fail-closed)")
	}

	p.store.putHostKeys(connID, r.HostKeys)
	// Remember which key authorized this connection so PipeStart can attribute
	// the session audit; the last success before PipeStart is the authenticator.
	p.store.putSessionAttr(connID, fingerprint, route.AuthPublicKey)
	logRouteAllowed(base, r)
	return &libplugin.Upstream{
		Host:          r.IP,
		Port:          int32(r.Port),
		UserName:      r.User,
		IgnoreHostKey: false, // host key is pinned and verified below
		Auth:          libplugin.CreatePrivateKeyAuth(p.platformKey),
	}, nil
}

// passwordCallback is the per-VM opt-in passthrough path. The route API denies
// unless the VM has ssh_password_enabled; on success the typed password is
// passed straight through to the VM's own sshd. This path has no per-user
// identity (documented, per-VM limitation), so it is not memoized. Fail-closed.
func (p *Plugin) passwordCallback(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	slug := conn.User()
	sourceIP := hostFromAddr(conn.RemoteAddr())
	connID := conn.UniqueID()

	r, err := p.resolver.Resolve(context.Background(), route.Request{
		Slug: slug, SourceIP: sourceIP, AuthMethod: route.AuthPassword, ConnectionID: connID,
	})
	base := log.Fields{
		"slug": slug, "sourceIp": sourceIP, "authMethod": route.AuthPassword,
	}
	if err != nil {
		logResolveErr(base, err)
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("gateway: resolver returned no route and no error (fail-closed)")
	}

	p.store.putHostKeys(connID, r.HostKeys)
	// Password sessions carry no per-user identity: record the method only, no
	// fingerprint, so the session audit attributes actor=null (documented G6 opt-in).
	p.store.putSessionAttr(connID, "", route.AuthPassword)
	logRouteAllowed(base, r)
	return &libplugin.Upstream{
		Host:          r.IP,
		Port:          int32(r.Port),
		UserName:      r.User,
		IgnoreHostKey: false, // host key is pinned and verified below
		Auth:          libplugin.CreatePasswordAuth(password),
	}, nil
}

// verifyHostKeyCallback pins the upstream host key against the set the route API
// returned for this connection. It is fail-closed: if no pinned set was stored
// (a host-key verify with no preceding successful route, or an expired memo),
// or the presented key matches none of the pinned entries, the session is
// refused. This replaces the v1 IgnoreHostKey:true trust.
func (p *Plugin) verifyHostKeyCallback(conn libplugin.ConnMetadata, hostname, netaddr string, keyBlob []byte) error {
	connID := conn.UniqueID()
	pinned, ok := p.store.getHostKeys(connID)
	if !ok || len(pinned) == 0 {
		log.WithFields(log.Fields{
			"connId": connID, "hostname": hostname, "netaddr": netaddr,
		}).Error("sshgw host-key verify with no pinned key (fail-closed)")
		return fmt.Errorf("gateway: no pinned host key for connection %q", connID)
	}

	presented, err := ssh.ParsePublicKey(keyBlob)
	if err != nil {
		return fmt.Errorf("gateway: parse upstream host key: %w", err)
	}
	presentedWire := presented.Marshal()

	for _, line := range pinned {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			// A malformed pinned entry cannot match; skip rather than trust.
			log.WithFields(log.Fields{
				"connId": connID, "err": err.Error(),
			}).Warn("sshgw pinned host key entry unparseable, skipping")
			continue
		}
		if bytes.Equal(pk.Marshal(), presentedWire) {
			log.WithFields(log.Fields{
				"connId": connID, "hostname": hostname, "keyType": presented.Type(),
			}).Debug("sshgw upstream host key verified")
			return nil
		}
	}

	log.WithFields(log.Fields{
		"connId": connID, "hostname": hostname, "netaddr": netaddr,
		"presentedType": presented.Type(),
	}).Warn("sshgw upstream host key mismatch (fail-closed)")
	return fmt.Errorf("gateway: upstream host key mismatch for %q", hostname)
}

// resolveMemoized returns the memoized outcome for (connID, fingerprint) when
// present, otherwise calls the resolver once. Only a **structural** outcome is
// memoized — an allow (success) or a *route.Denial, both stable for the auth
// window. A transport/decode error is deliberately NOT memoized: caching a
// transient blip would pin the key to that failure for the whole ~2-min window
// and block the client's signed-stage retry (fail-closed either way, but
// needlessly). Leaving it unmemoized lets the natural retry re-attempt.
func (p *Plugin) resolveMemoized(connID string, req route.Request) (*route.Route, error) {
	if e, ok := p.store.memoGet(connID, req.PublicKeyFingerprint); ok {
		return e.route, e.err
	}
	r, err := p.resolver.Resolve(context.Background(), req)
	if err == nil || isDenial(err) {
		p.store.memoPut(connID, req.PublicKeyFingerprint, memoEntry{route: r, err: err})
	}
	return r, err
}

// isDenial reports whether err is a structural route decision (*route.Denial)
// rather than a transport/decode failure.
func isDenial(err error) bool {
	var d *route.Denial
	return errors.As(err, &d)
}

// pipeStartCallback fires once per established session, after downstream
// signature verification (publickey) or password acceptance. It emits the
// authenticated per-user session audit (sshgw.session, G6) for the credential
// that actually authenticated — recovered from the connStore attribution keyed
// by connection id. The audit runs in a goroutine: sshpiperd invokes this
// synchronously right before it starts piping bytes, so it must return
// immediately and never let the audit hop delay or affect the live session.
func (p *Plugin) pipeStartCallback(conn libplugin.ConnMetadata) {
	req, ok := p.buildSessionRequest(conn)
	if !ok {
		// No recorded attribution for this connection (e.g. an auth path we did
		// not record, or an expired entry). Nothing to audit; skip harmlessly.
		log.WithFields(log.Fields{
			"connId": conn.UniqueID(),
		}).Debug("sshgw pipe start with no session attribution, skipping audit")
		return
	}
	go p.sendSessionAudit(req)
}

// buildSessionRequest assembles the session-audit request from the connection
// and the stored attribution. ok is false when no attribution was recorded.
func (p *Plugin) buildSessionRequest(conn libplugin.ConnMetadata) (route.Request, bool) {
	connID := conn.UniqueID()
	fingerprint, authMethod, ok := p.store.getSessionAttr(connID)
	if !ok {
		return route.Request{}, false
	}
	req := route.Request{
		Slug:         conn.User(),
		SourceIP:     hostFromAddr(conn.RemoteAddr()),
		AuthMethod:   authMethod,
		ConnectionID: connID,
	}
	if authMethod == route.AuthPublicKey {
		req.PublicKeyFingerprint = fingerprint
	}
	return req, true
}

// sendSessionAudit performs the fire-and-forget session-audit POST under a short
// timeout. A failure is logged and dropped — the session is already live and is
// never gated on this call.
func (p *Plugin) sendSessionAudit(req route.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), sessionAuditTimeout)
	defer cancel()
	if err := p.resolver.SessionStart(ctx, req); err != nil {
		log.WithFields(log.Fields{
			"slug": req.Slug, "sourceIp": req.SourceIP,
			"authMethod": req.AuthMethod, "connId": req.ConnectionID,
			"err": err.Error(),
		}).Warn("sshgw session audit failed (best-effort, session unaffected)")
		return
	}
	log.WithFields(log.Fields{
		"slug": req.Slug, "sourceIp": req.SourceIP,
		"authMethod": req.AuthMethod, "connId": req.ConnectionID,
	}).Info("sshgw session audited")
}

// logResolveErr logs a route failure, distinguishing a structured denial (an
// operational signal at Warn) from a transport/decode failure (an error).
func logResolveErr(base log.Fields, err error) {
	var d *route.Denial
	if errors.As(err, &d) {
		base["httpStatus"] = d.HTTPStatus
		base["reason"] = d.Machine()
		log.WithFields(base).Warn("sshgw route denied")
		return
	}
	base["err"] = err.Error()
	log.WithFields(base).Error("sshgw route lookup failed (fail-closed)")
}

func logRouteAllowed(base log.Fields, r *route.Route) {
	base["upstream"] = r.IP
	base["upstreamPort"] = r.Port
	base["upstreamUser"] = r.User
	log.WithFields(base).Info("sshgw route allowed")
}

// hostFromAddr strips the port from a "host:port" RemoteAddr, tolerating a bare
// host. The result is the real client IP reported to the route API as sourceIp.
func hostFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
