// Command sshgw-proxyfront is the PROXY-protocol-required ingress shim for the
// Pickle SSH gateway. It listens on the WireGuard interface address, enforces
// that every connection opens with a valid PROXY v2 header from the WireGuard
// peer (dropping headerless/malformed/non-peer connections with no SSH bytes),
// and forwards to loopback sshpiperd, re-emitting the recovered real client IP.
//
// Configuration is from flags or the environment:
//
//	SSHGW_PROXYFRONT_LISTEN     ingress addr        (default 10.100.100.2:22)
//	SSHGW_PROXYFRONT_UPSTREAM   loopback sshpiperd  (default 127.0.0.1:2222)
//	SSHGW_PROXYFRONT_PEER       trusted WG peer CIDR (default 10.100.100.1/32)
package main

import (
	"os"

	"github.com/pickle/sshgw/internal/proxyfront"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "sshgw-proxyfront",
		Usage: "PROXY-required ingress shim fronting sshpiperd",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "listen",
				Value:   "10.100.100.2:22",
				EnvVars: []string{"SSHGW_PROXYFRONT_LISTEN"},
				Usage:   "ingress address (bind to the WireGuard interface addr)",
			},
			&cli.StringFlag{
				Name:    "upstream",
				Value:   "127.0.0.1:2222",
				EnvVars: []string{"SSHGW_PROXYFRONT_UPSTREAM"},
				Usage:   "loopback sshpiperd address",
			},
			&cli.StringFlag{
				Name:    "peer",
				Value:   "10.100.100.1/32",
				EnvVars: []string{"SSHGW_PROXYFRONT_PEER"},
				Usage:   "trusted WireGuard peer CIDR (must send a valid PROXY header)",
			},
		},
		Action: func(c *cli.Context) error {
			srv, err := proxyfront.Listen(proxyfront.Config{
				Listen:        c.String("listen"),
				Upstream:      c.String("upstream"),
				TrustedRanges: []string{c.String("peer")},
			})
			if err != nil {
				return err
			}
			log.WithFields(log.Fields{
				"listen": c.String("listen"), "upstream": c.String("upstream"),
				"peer": c.String("peer"),
			}).Info("sshgw-proxyfront listening (PROXY v2 required, peer-only)")
			return srv.Serve()
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.WithField("err", err.Error()).Fatal("sshgw-proxyfront exited")
	}
}
