package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func newEnrollCmd() *cobra.Command {
	var (
		host      string
		token     string
		tokenFile string
		insecure  bool
		force     bool
	)
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this agent with XDR using a one-time enrollment token",
		Long: `Registers the agent with xdr-enrollment (CSR + token), stores the signed
certificate in OS secure storage (Keychain / machine-scope DPAPI / sealed file),
then clears the bootstrap token from disk.

Token sources (first match wins):
  1) --token
  2) --token-file / xdr.enrollment_token_file / env XDR_ENROLLMENT_TOKEN_FILE
  3) configDir/enrollment.token (installer sidecar)
  4) xdr.enrollment_token / env XDR_ENROLLMENT_TOKEN
  5) interactive prompt (when stdin is a terminal)

Examples (same on Windows, macOS, and Linux; Windows may omit sudo):
  edrctl enroll --token "$TOKEN"
  edrctl enroll --token-file /etc/edr-agent/enrollment.token
  edrctl enroll --force --token "$TOKEN"   # replace existing device identity`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requirePrivileged(); err != nil {
				return err
			}
			if strings.TrimSpace(token) == "" {
				if t, err := promptEnrollmentToken(); err != nil {
					return err
				} else if t != "" {
					token = t
				}
			}
			cfgPath := configFile
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config %s: %w", cfgPath, err)
			}

			boot, err := xdrclient.ApplyBootstrap(&cfg.XDR, xdrclient.BootstrapOverrides{
				Host:            host,
				Token:           token,
				TokenFile:       tokenFile,
				InsecureSkipTLS: insecure,
				InsecureSet:     cmd.Flags().Changed("insecure"),
				ConfigDir:       filepath.Dir(cfgPath),
				DataDir:         cfg.Agent.DataDir,
			})
			if err != nil {
				return err
			}
			if strings.TrimSpace(cfg.XDR.EnrollmentHost) == "" {
				cfg.XDR.EnrollmentHost = xdrclient.DefaultEnrollmentHost
			}
			cfg.XDR.Enabled = true

			if !cfg.XDR.HasBootstrapCredentials() {
				return fmt.Errorf("enrollment requires --host and a token (--token, --token-file, env, or %s)",
					xdrclient.DefaultEnrollmentTokenPath(filepath.Dir(cfgPath)))
			}

			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			res, err := xdrclient.EnsureEnrolled(ctx, xdrclient.EnrollOptions{
				Config:        cfg.XDR,
				AgentID:       cfg.Agent.ID,
				AgentVer:      firstNonEmpty(cfg.Agent.Version, version),
				DataDir:       cfg.Agent.DataDir,
				Logger:        slog.Default(),
				ConfigPath:    cfgPath,
				TokenFileUsed: boot.TokenFileUsed,
				Force:         force,
			})
			if err != nil {
				return err
			}
			if res.Fresh {
				fmt.Printf("enrolled agent_id=%s secure_storage=%s ingest=%v cert_not_after=%s\n",
					res.State.AgentID, res.State.SecureStorage, res.State.IngestHosts,
					res.State.CertNotAfter.Format(time.RFC3339))
			} else {
				fmt.Printf("credentials loaded agent_id=%s secure_storage=%s ingest=%v\n",
					res.State.AgentID, res.State.SecureStorage, res.State.IngestHosts)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "enrollment host:port (or XDR_ENROLLMENT_HOST)")
	cmd.Flags().StringVar(&token, "token", "", "one-time enrollment token (or XDR_ENROLLMENT_TOKEN)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "path to token file (or XDR_ENROLLMENT_TOKEN_FILE)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "use insecure gRPC to enrollment (lab/dev)")
	cmd.Flags().BoolVar(&force, "force", false, "re-enroll even if credentials already exist")
	return cmd
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func promptEnrollmentToken() (string, error) {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return "", nil
	}
	fmt.Fprint(os.Stderr, "Enrollment token: ")
	var line string
	if _, err := fmt.Scanln(&line); err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	return strings.TrimSpace(line), nil
}
