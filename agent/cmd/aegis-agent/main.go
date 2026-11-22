// Command aegis-agent collects security telemetry and delivers it to an AEGIS server.
//
//	aegis-agent validate-config -config agent.json
//	aegis-agent enroll -config agent.json -token-file token.txt [-hostname H]
//	aegis-agent run -config agent.json
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"aegis/agent/internal/config"
	"aegis/agent/internal/runner"
	"aegis/agent/internal/state"
	"aegis/agent/internal/uploader"
)

const (
	exitOK      = 0
	exitUsage   = 2
	exitRevoked = 3
	exitError   = 1
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to agent configuration (JSON)")
	tokenFile := fs.String("token-file", "", "file containing a single-use enrollment token")
	hostname := fs.String("hostname", "", "hostname to register (default: OS hostname)")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "-config is required")
		return exitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid configuration:", err)
		return exitUsage
	}
	uploader.UserAgent = "aegis-agent/" + runner.Version
	switch args[0] {
	case "validate-config":
		fmt.Printf("configuration valid (schema %d, config_version %d, %d sources)\n",
			cfg.SchemaVersion, cfg.ConfigVersion, len(cfg.Sources))
		return exitOK
	case "enroll":
		return enroll(cfg, *tokenFile, *hostname)
	case "run":
		id, err := state.LoadIdentity(cfg.StateDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		r, err := runner.New(cfg, id, log)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitError
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		log.Info("agent started", "version", runner.Version, "agent_id", id.AgentID, "sources", len(cfg.Sources))
		err = r.Run(ctx)
		if errors.Is(err, uploader.ErrRevoked) {
			fmt.Fprintln(os.Stderr, "agent credential was revoked or expired; re-enroll to resume")
			return exitRevoked
		}
		log.Info("agent stopped")
		return exitOK
	}
	usage()
	return exitUsage
}

func enroll(cfg *config.Config, tokenFile, hostname string) int {
	if tokenFile == "" {
		fmt.Fprintln(os.Stderr, "-token-file is required (tokens are not accepted on the command line)")
		return exitUsage
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read token:", err)
		return exitError
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := uploader.New(cfg.ServerURL, "")
	res, err := c.Enroll(ctx, strings.TrimSpace(string(raw)), hostname, runtime.GOOS, runner.Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "enrollment failed:", err)
		return exitError
	}
	if err := state.SaveIdentity(cfg.StateDir, &state.Identity{
		AgentID: res.AgentID, TenantID: res.TenantID, Credential: res.Credential,
		CredentialExpiresAt: res.CredentialExpiresAt,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "save identity:", err)
		return exitError
	}
	fmt.Printf("enrolled as %s (tenant %s); delete the token file now\n", res.AgentID, res.TenantID)
	return exitOK
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: aegis-agent {validate-config|enroll|run} -config agent.json [-token-file f]")
}
