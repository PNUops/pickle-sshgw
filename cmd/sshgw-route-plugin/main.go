// Command sshgw-route-plugin is the sshpiperd gRPC plugin for the Pickle SSH
// gateway. sshpiperd launches it as a subprocess and calls its PasswordCallback
// for each connection; the plugin resolves the SSH slug against pickle-api
// (POST /internal/sshgw/route) and pipes the session to the user's VM,
// passing the typed password through.
//
// Configuration is from the environment (or --api-base / --token flags):
//
//	PICKLE_SSHGW_API_BASE  pickle-api base URL, e.g. http://172.30.1.20:8080
//	PICKLE_SSHGW_TOKEN     shared bearer token (required — fail-closed if unset)
//
// It is fail-closed: with no token the plugin refuses to start, and any route
// lookup error refuses the SSH session.
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
			return gateway.New(client).Config(), nil
		},
	})
}
