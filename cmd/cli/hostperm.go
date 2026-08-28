package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/hostperm"
	"github.com/razatechofficial/edr/internal/updatecheck"
)

func newHostpermCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hostperm",
		Short: "Show OS permission and persistence catalog",
		Long:  "Evaluates Full Disk Access, boot persistence, login items, and the offline spool. JSON for the desktop console.",
		RunE: func(cmd *cobra.Command, args []string) error {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(hostperm.Evaluate())
		},
	}
}

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Enterprise update catalog (check only; MDM installs)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Compare this build to the configured catalog URL",
		RunE: func(cmd *cobra.Command, args []string) error {
			url := ""
			if cfg, err := config.Load(configFile); err == nil {
				url = cfg.XDR.UpdateCatalogURL
			}
			r := updatecheck.Check(version, url, nil)
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(r); err != nil {
				return err
			}
			if r.Error != "" {
				return fmt.Errorf("%s", r.Error)
			}
			return nil
		},
	})
	return cmd
}
