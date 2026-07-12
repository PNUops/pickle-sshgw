// Package gateway wires the route-resolution client into an sshpiperd plugin
// callback. On every incoming SSH connection sshpiperd invokes PasswordCallback
// with the SSH username (the VM slug) and the downstream RemoteAddr (the real
// client IP, recovered from the PROXY protocol header by the ingress shim and
// re-parsed by sshpiperd). The callback asks pickle-api where to route, and on
// success pipes the session to the VM passing the typed password through to the
// VM's own sshd (v1 shared-password model). Every failure refuses the session.
package gateway

import (
	"context"
	"errors"
	"net"

	"github.com/pickle/sshgw/internal/route"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
)

// Resolver resolves a slug + source IP to an upstream route. *route.Client
// implements it; tests substitute a fake.
type Resolver interface {
	Resolve(ctx context.Context, slug, sourceIP string) (*route.Route, error)
}

// Plugin holds the callback dependencies.
type Plugin struct {
	resolver Resolver
}

// New builds a Plugin from a resolver.
func New(resolver Resolver) *Plugin {
	return &Plugin{resolver: resolver}
}

// Config returns the sshpiperd plugin config. Only password auth is wired: the
// SSH username selects the route and the typed password is passed through to
// the VM. Public-key (per-user identity) is roadmap 09.
func (p *Plugin) Config() *libplugin.SshPiperPluginConfig {
	return &libplugin.SshPiperPluginConfig{
		PasswordCallback: p.passwordCallback,
	}
}

// passwordCallback is the routing decision point. It is fail-closed: any error
// (denial, transport, decode) returns a nil upstream and an error, which
// sshpiperd surfaces to the client as an auth failure — never a pipe to a
// default/last-known target.
func (p *Plugin) passwordCallback(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	slug := conn.User()
	sourceIP := hostFromAddr(conn.RemoteAddr())

	r, err := p.resolver.Resolve(context.Background(), slug, sourceIP)
	if err != nil {
		var d *route.Denial
		if errors.As(err, &d) {
			log.WithFields(log.Fields{
				"slug": slug, "sourceIp": sourceIP,
				"httpStatus": d.HTTPStatus, "reason": d.Machine(),
			}).Warn("sshgw route denied")
		} else {
			log.WithFields(log.Fields{
				"slug": slug, "sourceIp": sourceIP, "err": err.Error(),
			}).Error("sshgw route lookup failed (fail-closed)")
		}
		return nil, err
	}

	log.WithFields(log.Fields{
		"slug": slug, "sourceIp": sourceIP,
		"upstream": r.IP, "upstreamPort": r.Port, "upstreamUser": r.User,
	}).Info("sshgw route allowed")

	return &libplugin.Upstream{
		Host: r.IP,
		Port: int32(r.Port),
		// v1 has no per-VM host key in the route response, so this hop is not
		// host-key-verified. Trust rests on the hop staying inside the guest
		// bridge (172.29/16): an attacker must already be on that L2 segment to
		// spoof the target and capture the passed-through password. Closing that
		// L2 path is launch gate G1 (per-NIC ipfilter/anti-spoof); host-key
		// pinning here arrives with the roadmap per-user-key work. See
		// docs/plan/05-ssh-access.md and docs/plan/12-production-gates.md.
		IgnoreHostKey: true,
		UserName:      r.User,
		// Pass the client's typed password straight through to the VM sshd.
		Auth: libplugin.CreatePasswordAuth(password),
	}, nil
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
