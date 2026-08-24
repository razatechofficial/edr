package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/razatechofficial/edr/internal/xdrclient"
)

func newUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ui",
		Short: "Operator dashboard (status, enrollment, detections)",
		Long:  "Prints a compact ASCII dashboard suitable for Windows/macOS Start Menu/Applications shortcuts and Linux terminals without a GUI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return printOperatorDashboard(os.Stdout)
		},
	}
}

func newTestConnectionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test-connection",
		Short: "Test enrollment and ingest host reachability",
		RunE: func(cmd *cobra.Command, args []string) error {
			hosts, err := connectionTargets()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TARGET\tRESULT")
			var failed int
			for _, host := range hosts {
				if err := probeTCP(host, 5*time.Second); err != nil {
					fmt.Fprintf(w, "%s\tunreachable (%v)\n", host, err)
					failed++
					continue
				}
				fmt.Fprintf(w, "%s\tok\n", host)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d host(s) unreachable", failed)
			}
			return nil
		},
	}
}

func printOperatorDashboard(out *os.File) error {
	fmt.Fprintln(out, "╔══════════════════════════════════════════════════════╗")
	fmt.Fprintln(out, "║                   EDR Agent                          ║")
	fmt.Fprintln(out, "╚══════════════════════════════════════════════════════╝")

	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "Config:\t%s\n", configFile)

	svc := serviceRuntimeStatus()
	fmt.Fprintf(w, "Service:\t%s\n", svc)

	enrolled, agentID, ingest := enrollmentSnapshot()
	if enrolled {
		fmt.Fprintf(w, "Enrollment:\tenrolled\n")
		if agentID != "" {
			fmt.Fprintf(w, "Agent ID:\t%s\n", agentID)
		}
		if ingest != "" {
			fmt.Fprintf(w, "Ingest:\t%s\n", ingest)
		}
	} else {
		fmt.Fprintf(w, "Enrollment:\tidle (not enrolled)\n")
		fmt.Fprintln(w, "Next:\tedrctl enroll --token <token>")
	}

	body, err := agentRequest("GET", "/api/v1/status", nil)
	if err != nil {
		fmt.Fprintf(w, "Control API:\tunavailable\n")
		fmt.Fprintf(w, "Detections:\tn/a (agent not responding)\n")
		fmt.Fprintf(w, "Blocks:\tn/a\n")
	} else {
		var status struct {
			Status    string `json:"status"`
			Version   string `json:"version"`
			Uptime    string `json:"uptime"`
			AlertsGen uint64 `json:"alerts_generated"`
			Isolated  bool   `json:"isolated"`
		}
		if json.Unmarshal(body, &status) == nil {
			fmt.Fprintf(w, "Runtime:\t%s\n", emptyDash(status.Status))
			fmt.Fprintf(w, "Version:\t%s\n", emptyDash(status.Version))
			fmt.Fprintf(w, "Uptime:\t%s\n", emptyDash(status.Uptime))
			fmt.Fprintf(w, "Local detections:\t%d\n", status.AlertsGen)
			if status.Isolated {
				fmt.Fprintf(w, "Containment:\tISOLATED\n")
			} else {
				fmt.Fprintf(w, "Containment:\tnormal\n")
			}
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Connection test")
	hosts, herr := connectionTargets()
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tRESULT")
	if herr != nil {
		fmt.Fprintf(tw, "-\t%s\n", herr)
	} else {
		for _, host := range hosts {
			if err := probeTCP(host, 4*time.Second); err != nil {
				fmt.Fprintf(tw, "%s\tfail\n", host)
				continue
			}
			fmt.Fprintf(tw, "%s\tok\n", host)
		}
	}
	return tw.Flush()
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

type enrollMeta struct {
	AgentID     string   `json:"agent_id"`
	IngestHosts []string `json:"ingest_hosts"`
}

func enrollmentSnapshot() (enrolled bool, agentID, ingest string) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false, "", ""
	}
	var peek yamlConfigPeek
	_ = yaml.Unmarshal(data, &peek)
	dataDir := peek.Agent.DataDir
	if dataDir == "" {
		return peek.Agent.ID != "", peek.Agent.ID, ""
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "xdr-tls", "enrollment.json"))
	if err != nil {
		return peek.Agent.ID != "", peek.Agent.ID, ""
	}
	var meta enrollMeta
	if json.Unmarshal(raw, &meta) != nil {
		return peek.Agent.ID != "", peek.Agent.ID, ""
	}
	ingest = strings.Join(meta.IngestHosts, ",")
	id := meta.AgentID
	if id == "" {
		id = peek.Agent.ID
	}
	return id != "" && len(meta.IngestHosts) > 0, id, ingest
}

func connectionTargets() ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	add(xdrclient.DefaultEnrollmentHost)
	add(xdrclient.DefaultIngestHost)

	data, err := os.ReadFile(configFile)
	if err == nil {
		var cfg struct {
			XDR struct {
				EnrollmentHost string   `yaml:"enrollment_host"`
				IngestHosts    []string `yaml:"ingest_hosts"`
			} `yaml:"xdr"`
		}
		if yaml.Unmarshal(data, &cfg) == nil {
			add(cfg.XDR.EnrollmentHost)
			for _, h := range cfg.XDR.IngestHosts {
				add(h)
			}
		}
	}
	_, _, ingest := enrollmentSnapshot()
	for _, h := range strings.Split(ingest, ",") {
		add(h)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no enrollment/ingest hosts configured")
	}
	return out, nil
}

func probeTCP(host string, timeout time.Duration) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return fmt.Errorf("empty host")
	}
	if _, _, err := net.SplitHostPort(h); err != nil {
		h = net.JoinHostPort(h, "443")
	}
	c, err := net.DialTimeout("tcp", h, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}
