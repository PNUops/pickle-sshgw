// Command sshgw-terminal-bridge terminates the Pickle web-terminal browser
// WebSocket on the sshgw LXC (172.30.1.30) and relays it to the user's VM over a
// locked-down SSH connection. It is the enforcer half of the control/data-plane
// split:
// pickle-api mints one-time tickets and answers the bridge's internal control
// calls, while this daemon owns the real WS+SSH session and reports it back.
//
// It runs two listeners: the browser-WS ingress (default :8082, source-restricted
// to the LXC 100 nginx tier) and the api→bridge control port (default :8083,
// source-restricted to pickle-api). It holds no DB, no Proxmox token and no
// credential-cipher key. Configuration is from the environment (or matching
// flags):
//
//	PICKLE_TERMINAL_WS_LISTEN        browser-WS ingress addr      (default 172.30.1.30:8082)
//	PICKLE_TERMINAL_CONTROL_LISTEN   control addr                 (default 172.30.1.30:8083)
//	PICKLE_SSHGW_API_BASE            pickle-api base URL          (default http://172.30.1.20:8080)
//	PICKLE_SSHGW_TOKEN               bridge→api bearer (required — fail-closed if unset)
//	PICKLE_TERMINAL_CONTROL_TOKEN    inbound control bearer (required — fail-closed if unset)
//	PICKLE_TERMINAL_CONSOLE_ORIGIN   exact browser Origin         (default https://pickle.pusan.ac.kr)
//	PICKLE_TERMINAL_KEY_FILE         platform terminal ed25519 key (default /etc/pickle/sshgw/terminal_ed25519_key)
//	PICKLE_TERMINAL_WS_PEER          allowed WS peer (nginx)       (default 172.30.1.10)
//	PICKLE_TERMINAL_CONTROL_PEER     allowed control peer (api)    (default 172.30.1.20)
//	PICKLE_TERMINAL_IDLE_TIMEOUT     idle timeout                 (default 15m)
//	PICKLE_TERMINAL_PING_INTERVAL    server WS ping cadence       (default 30s)
//	PICKLE_TERMINAL_REVALIDATE_INTERVAL  revalidation poll cadence (default 60s)
//	PICKLE_TERMINAL_MAX_FRAME        WS read limit bytes          (default 1048576)
//	PICKLE_TERMINAL_MAX_SESSIONS     global concurrent-session cap (default 200)
//
// It is fail-closed: a missing token or an unreadable/invalid terminal key aborts
// startup.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pickle/sshgw/internal/terminal"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "sshgw-terminal-bridge",
		Usage: "Pickle web-terminal bridge (browser WS → locked-down SSH to the VM)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "ws-listen", Value: terminal.DefaultWSListen, EnvVars: []string{"PICKLE_TERMINAL_WS_LISTEN"}, Usage: "browser-WS ingress address"},
			&cli.StringFlag{Name: "control-listen", Value: terminal.DefaultControlListen, EnvVars: []string{"PICKLE_TERMINAL_CONTROL_LISTEN"}, Usage: "api→bridge control address"},
			&cli.StringFlag{Name: "api-base", Value: terminal.DefaultAPIBase, EnvVars: []string{"PICKLE_SSHGW_API_BASE"}, Usage: "pickle-api base URL"},
			&cli.StringFlag{Name: "token", EnvVars: []string{"PICKLE_SSHGW_TOKEN"}, Usage: "bridge→api bearer token (required)"},
			&cli.StringFlag{Name: "control-token", EnvVars: []string{"PICKLE_TERMINAL_CONTROL_TOKEN"}, Usage: "inbound control bearer token (required)"},
			&cli.StringFlag{Name: "console-origin", Value: terminal.DefaultConsoleOrigin, EnvVars: []string{"PICKLE_TERMINAL_CONSOLE_ORIGIN"}, Usage: "exact browser Origin to accept"},
			&cli.StringFlag{Name: "key-file", Value: terminal.DefaultTerminalKeyFile, EnvVars: []string{"PICKLE_TERMINAL_KEY_FILE"}, Usage: "platform terminal ed25519 private key"},
			&cli.StringFlag{Name: "ws-peer", Value: terminal.DefaultWSAllowedSourceIP, EnvVars: []string{"PICKLE_TERMINAL_WS_PEER"}, Usage: "allowed WS peer IP (nginx tier)"},
			&cli.StringFlag{Name: "control-peer", Value: terminal.DefaultControlSourceIP, EnvVars: []string{"PICKLE_TERMINAL_CONTROL_PEER"}, Usage: "allowed control peer IP (pickle-api)"},
			&cli.DurationFlag{Name: "idle-timeout", Value: terminal.DefaultIdleTimeout, EnvVars: []string{"PICKLE_TERMINAL_IDLE_TIMEOUT"}, Usage: "idle timeout (client input only)"},
			&cli.DurationFlag{Name: "ping-interval", Value: terminal.DefaultPingInterval, EnvVars: []string{"PICKLE_TERMINAL_PING_INTERVAL"}, Usage: "server WS ping cadence"},
			&cli.DurationFlag{Name: "revalidate-interval", Value: terminal.DefaultRevalidateInterval, EnvVars: []string{"PICKLE_TERMINAL_REVALIDATE_INTERVAL"}, Usage: "revalidation poll cadence"},
			&cli.Int64Flag{Name: "max-frame", Value: terminal.DefaultMaxFrameBytes, EnvVars: []string{"PICKLE_TERMINAL_MAX_FRAME"}, Usage: "WS read limit in bytes (client→bridge)"},
			&cli.IntFlag{Name: "max-sessions", Value: terminal.DefaultMaxSessions, EnvVars: []string{"PICKLE_TERMINAL_MAX_SESSIONS"}, Usage: "global concurrent-session hard cap"},
		},
		Action: run,
	}
	if err := app.Run(os.Args); err != nil {
		log.WithField("err", err.Error()).Fatal("sshgw-terminal-bridge exited")
	}
}

func run(c *cli.Context) error {
	cfg := terminal.Config{
		WSListen:               c.String("ws-listen"),
		ControlListen:          c.String("control-listen"),
		APIBase:                c.String("api-base"),
		GatewayToken:           c.String("token"),
		ControlToken:           c.String("control-token"),
		ConsoleOrigin:          c.String("console-origin"),
		TerminalKeyFile:        c.String("key-file"),
		WSAllowedSourceIP:      c.String("ws-peer"),
		ControlAllowedSourceIP: c.String("control-peer"),
		IdleTimeout:            c.Duration("idle-timeout"),
		PingInterval:           c.Duration("ping-interval"),
		RevalidateInterval:     c.Duration("revalidate-interval"),
		MaxFrameBytes:          c.Int64("max-frame"),
		MaxSessions:            c.Int("max-sessions"),
	}
	if err := cfg.Validate(); err != nil {
		return err // fail-closed: missing token / origin / key path
	}
	signer, err := terminal.LoadTerminalKey(cfg.TerminalKeyFile)
	if err != nil {
		return err // fail-closed: no/invalid terminal key
	}
	api := terminal.NewAPIClient(cfg.APIBase, cfg.GatewayToken, cfg.APITimeout)
	bridge := terminal.NewBridge(cfg, signer, api)

	wsMux := http.NewServeMux()
	wsMux.Handle("/terminal/ws", bridge.WSHandler())
	wsSrv := &http.Server{Addr: cfg.WSListen, Handler: wsMux}

	ctrlMux := http.NewServeMux()
	ctrlMux.Handle("/control/terminate", bridge.ControlHandler())
	ctrlSrv := &http.Server{Addr: cfg.ControlListen, Handler: ctrlMux}

	errCh := make(chan error, 2)
	go func() { errCh <- wsSrv.ListenAndServe() }()
	go func() { errCh <- ctrlSrv.ListenAndServe() }()
	log.WithFields(log.Fields{
		"wsListen": cfg.WSListen, "controlListen": cfg.ControlListen, "apiBase": cfg.APIBase,
	}).Info("sshgw-terminal-bridge listening")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		log.WithField("signal", sig.String()).Info("sshgw-terminal-bridge shutting down")
		// Close all live sessions (1001 + BRIDGE_SHUTDOWN) before draining HTTP.
		bridge.Shutdown()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = wsSrv.Shutdown(ctx)
		_ = ctrlSrv.Shutdown(ctx)
		return nil
	}
}
