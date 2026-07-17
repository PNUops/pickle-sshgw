// Command sshgw-route-plugin is the sshpiperd gRPC plugin for the Pickle SSH
// gateway. sshpiperd launches it as a subprocess and calls its PasswordCallback
// for each connection; the plugin resolves the SSH slug against pickle-api
// (POST /internal/sshgw/route) and pipes the session to the user's VM,
// passing the typed password through.
//
// Configuration is from the environment (or matching flags):
//
//	PICKLE_SSHGW_API_BASE         pickle-api base URL, e.g. http://172.30.1.20:8080
//	PICKLE_SSHGW_TOKEN            shared bearer token (required — fail-closed if unset)
//	PICKLE_SSHGW_UPSTREAM_KEY_FILE platform ed25519 private key for the gateway→VM
//	                              hop (default /etc/pickle/sshgw/upstream_ed25519_key)
//
// It is fail-closed: with no token, or an unreadable/invalid upstream key, the
// plugin refuses to start, and any route lookup error refuses the SSH session.
package main

import (
	"github.com/pickle/sshgw/internal/gateway"
	"github.com/pickle/sshgw/internal/route"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "sshgw-route",
		Usage: "Pickle SSH gateway routing plugin (resolves slug via pickle-api, password passthrough)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "api-base",
				Usage:   "pickle-api base URL for the internal route endpoint",
				EnvVars: []string{"PICKLE_SSHGW_API_BASE"},
			},
			&cli.StringFlag{
				Name:    "token",
				Usage:   "shared bearer token (PICKLE_SSHGW_TOKEN); required",
				EnvVars: []string{"PICKLE_SSHGW_TOKEN"},
			},
			&cli.DurationFlag{
				Name:    "timeout",
				Usage:   "per-lookup HTTP timeout",
				Value:   route.DefaultTimeout,
				EnvVars: []string{"PICKLE_SSHGW_TIMEOUT"},
			},
			&cli.StringFlag{
				Name:    "upstream-key-file",
				Usage:   "platform ed25519 private key for the gateway→VM hop",
				Value:   "/etc/pickle/sshgw/upstream_ed25519_key",
				EnvVars: []string{"PICKLE_SSHGW_UPSTREAM_KEY_FILE"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			client, err := route.New(route.Config{
				BaseURL: c.String("api-base"),
				Token:   c.String("token"),
				Timeout: c.Duration("timeout"),
			})
			if err != nil {
				return nil, err // fail-closed: no token / no base URL → refuse to start
			}
			platformKey, err := gateway.LoadUpstreamKey(c.String("upstream-key-file"))
			if err != nil {
				return nil, err // fail-closed: no/invalid upstream key → refuse to start
			}
			return gateway.New(client, platformKey).Config(), nil
		},
	})
}
