// Package main implements the edrctl management CLI for the EDR agent.
// It provides commands for querying agent status, viewing alerts, triggering
// scans, managing network isolation, and controlling agent configuration.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

const (
	defaultSocketPath = "/var/run/edr-agent.sock"
	defaultHTTPAddr   = "http://127.0.0.1:9200"
	defaultAlertFile  = "/var/log/edr/alerts.jsonl"
	defaultConfigFile = "/etc/edr/agent.yaml"
)

var (
	socketPath string
	httpAddr   string
	alertFile  string
	configFile string
)

func main() {
	root := &cobra.Command{
		Use:   "edrctl",
		Short: "EDR agent management CLI",
		Long:  "Command-line interface for managing the EDR endpoint detection and response agent. Provides status monitoring, alert viewing, on-demand scanning, network isolation, forensics collection, and configuration management.",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&socketPath, "socket", defaultSocketPath, "agent control socket path")
	root.PersistentFlags().StringVar(&httpAddr, "addr", defaultHTTPAddr, "agent HTTP control address")
	root.PersistentFlags().StringVar(&alertFile, "alert-file", defaultAlertFile, "path to alerts JSONL file")
	root.PersistentFlags().StringVar(&configFile, "config", defaultConfigFile, "path to agent config file")

	root.AddCommand(
		newStatusCmd(),
		newAlertsCmd(),
		newScanCmd(),
		newIsolateCmd(),
		newReleaseCmd(),
		newForensicsCmd(),
		newRulesCmd(),
		newConfigCmd(),
		newVersionCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// ---------- status ----------

// newStatusCmd returns the status command that queries agent health via the
// local control socket or HTTP endpoint.
func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show agent health and runtime status",
		Long:  "Connects to the agent's local control interface and displays health status, uptime, version, loaded rule count, and resource usage.",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := agentRequest("GET", "/api/v1/status", nil)
			if err != nil {
				return fmt.Errorf("agent unreachable: %w", err)
			}

			var status struct {
				Status     string    `json:"status"`
				Version    string    `json:"version"`
				Uptime     string    `json:"uptime"`
				StartedAt  time.Time `json:"started_at"`
				PID        int       `json:"pid"`
				OS         string    `json:"os"`
				Arch       string    `json:"arch"`
				RulesCount int       `json:"rules_count"`
				CPUPercent float64   `json:"cpu_percent"`
				MemoryMB   float64   `json:"memory_mb"`
				EventsProc uint64    `json:"events_processed"`
				AlertsGen  uint64    `json:"alerts_generated"`
				Isolated   bool      `json:"isolated"`
			}
			if err := json.Unmarshal(body, &status); err != nil {
				return fmt.Errorf("parsing response: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Status:\t%s\n", status.Status)
			fmt.Fprintf(w, "Version:\t%s\n", status.Version)
			fmt.Fprintf(w, "Uptime:\t%s\n", status.Uptime)
			fmt.Fprintf(w, "PID:\t%d\n", status.PID)
			fmt.Fprintf(w, "OS/Arch:\t%s/%s\n", status.OS, status.Arch)
			fmt.Fprintf(w, "Rules Loaded:\t%d\n", status.RulesCount)
			fmt.Fprintf(w, "CPU Usage:\t%.1f%%\n", status.CPUPercent)
			fmt.Fprintf(w, "Memory:\t%.1f MB\n", status.MemoryMB)
			fmt.Fprintf(w, "Events Processed:\t%d\n", status.EventsProc)
			fmt.Fprintf(w, "Alerts Generated:\t%d\n", status.AlertsGen)
			if status.Isolated {
				fmt.Fprintf(w, "Network:\tISOLATED\n")
			} else {
				fmt.Fprintf(w, "Network:\tnormal\n")
			}
			return w.Flush()
		},
	}
}

// ---------- alerts ----------

// newAlertsCmd returns the alerts command for viewing recent detection alerts
// from the JSONL log file with optional time and severity filters.
func newAlertsCmd() *cobra.Command {
	var (
		since    string
		severity string
		limit    int
	)

	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "View recent alerts",
		Long:  "Reads alerts from the agent's JSONL alert file and displays them in tabular format. Supports filtering by recency (--since) and minimum severity (--severity).",
		RunE: func(cmd *cobra.Command, args []string) error {
			cutoff := time.Time{}
			if since != "" {
				dur, err := time.ParseDuration(since)
				if err != nil {
					return fmt.Errorf("invalid --since duration: %w", err)
				}
				cutoff = time.Now().Add(-dur)
			}

			f, err := os.Open(alertFile)
			if err != nil {
				return fmt.Errorf("opening alert file %s: %w", alertFile, err)
			}
			defer f.Close()

			type alertEntry struct {
				AlertID     string    `json:"alert_id"`
				RuleID      string    `json:"rule_id"`
				Severity    string    `json:"severity"`
				Score       int       `json:"score"`
				Title       string    `json:"title"`
				Timestamp   time.Time `json:"timestamp"`
				ProcessName string    `json:"process_name"`
				ProcessPID  int       `json:"process_pid"`
			}

			var alerts []alertEntry
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				var a alertEntry
				if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
					continue
				}
				if !cutoff.IsZero() && a.Timestamp.Before(cutoff) {
					continue
				}
				if severity != "" && !severityAtLeast(a.Severity, severity) {
					continue
				}
				alerts = append(alerts, a)
			}
			if err := sc.Err(); err != nil {
				return fmt.Errorf("reading alerts: %w", err)
			}

			sort.Slice(alerts, func(i, j int) bool {
				return alerts[i].Timestamp.After(alerts[j].Timestamp)
			})

			if limit > 0 && len(alerts) > limit {
				alerts = alerts[:limit]
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "TIMESTAMP\tSEVERITY\tSCORE\tRULE\tPROCESS\tPID\tTITLE\n")
			fmt.Fprintf(w, "---------\t--------\t-----\t----\t-------\t---\t-----\n")
			for _, a := range alerts {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\t%s\n",
					a.Timestamp.Format("2006-01-02 15:04:05"),
					strings.ToUpper(a.Severity),
					a.Score,
					a.RuleID,
					a.ProcessName,
					a.ProcessPID,
					truncate(a.Title, 50),
				)
			}
			fmt.Fprintf(w, "\nTotal: %d alerts\n", len(alerts))
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&since, "since", "", "show alerts since duration (e.g. 1h, 30m, 24h)")
	cmd.Flags().StringVar(&severity, "severity", "", "minimum severity filter (info|low|medium|high|critical)")
	cmd.Flags().IntVarP(&limit, "limit", "n", 100, "maximum number of alerts to display")

	return cmd
}

// ---------- scan ----------

// newScanCmd returns the scan command for triggering an on-demand file scan
// using YARA rules and hash-based IOC checking.
func newScanCmd() *cobra.Command {
	var filePath string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Trigger on-demand file scan (YARA + hash check)",
		Long:  "Sends a scan request to the agent for the specified file. The agent evaluates the file against loaded YARA rules and checks its hash against known IOC databases.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" {
				return fmt.Errorf("--file is required")
			}

			absPath, err := filepath.Abs(filePath)
			if err != nil {
				return fmt.Errorf("resolving path: %w", err)
			}

			if _, err := os.Stat(absPath); err != nil {
				return fmt.Errorf("file not found: %s", absPath)
			}

			payload, _ := json.Marshal(map[string]string{"path": absPath})
			body, err := agentRequest("POST", "/api/v1/scan", payload)
			if err != nil {
				return fmt.Errorf("scan request failed: %w", err)
			}

			var result struct {
				Path       string   `json:"path"`
				Clean      bool     `json:"clean"`
				Hashes     []string `json:"hashes"`
				YARAHits   []string `json:"yara_hits"`
				IOCMatches []string `json:"ioc_matches"`
				Duration   string   `json:"duration"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return fmt.Errorf("parsing scan result: %w", err)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "File:\t%s\n", result.Path)
			fmt.Fprintf(w, "Clean:\t%v\n", result.Clean)
			fmt.Fprintf(w, "Duration:\t%s\n", result.Duration)
			if len(result.Hashes) > 0 {
				fmt.Fprintf(w, "Hashes:\t%s\n", strings.Join(result.Hashes, ", "))
			}
			if len(result.YARAHits) > 0 {
				fmt.Fprintf(w, "YARA Hits:\t%s\n", strings.Join(result.YARAHits, ", "))
			}
			if len(result.IOCMatches) > 0 {
				fmt.Fprintf(w, "IOC Matches:\t%s\n", strings.Join(result.IOCMatches, ", "))
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVarP(&filePath, "file", "f", "", "path to the file to scan")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

// ---------- isolate ----------

// newIsolateCmd returns the isolate command that instructs the agent to
// activate network isolation on the host.
func newIsolateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "isolate",
		Short: "Network-isolate this host",
		Long:  "Instructs the agent to enforce network isolation, blocking all traffic except communication with the control plane. This is a containment action for active incidents.",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := agentRequest("POST", "/api/v1/isolate", nil)
			if err != nil {
				return fmt.Errorf("isolate request failed: %w", err)
			}
			return printActionResult(body)
		},
	}
}

// ---------- release ----------

// newReleaseCmd returns the release command that instructs the agent to
// remove network isolation from the host.
func newReleaseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "release",
		Short: "Release network isolation",
		Long:  "Instructs the agent to remove network isolation, restoring normal network connectivity. Only use after incident containment is complete.",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := agentRequest("POST", "/api/v1/release", nil)
			if err != nil {
				return fmt.Errorf("release request failed: %w", err)
			}
			return printActionResult(body)
		},
	}
}

// ---------- forensics ----------

// newForensicsCmd returns the forensics parent command with subcommands for
// triggering forensic evidence collection.
func newForensicsCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "forensics",
		Short: "Forensic evidence collection",
		Long:  "Commands for triggering and managing forensic evidence collection including memory dumps, disk artifacts, and chain-of-custody records.",
	}

	collectCmd := &cobra.Command{
		Use:   "collect",
		Short: "Trigger forensics collection on this host",
		Long:  "Instructs the agent to collect forensic artifacts including process memory, open file handles, network connections, loaded modules, and system state. Output is written to the configured forensics directory with chain-of-custody hashing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := agentRequest("POST", "/api/v1/forensics/collect", nil)
			if err != nil {
				return fmt.Errorf("forensics collect failed: %w", err)
			}
			return printActionResult(body)
		},
	}

	parent.AddCommand(collectCmd)
	return parent
}

// ---------- rules ----------

// newRulesCmd returns the rules parent command with subcommands for
// managing detection rules.
func newRulesCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "rules",
		Short: "Detection rule management",
		Long:  "Commands for managing detection rules including Sigma, YARA, and behavioral rules.",
	}

	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Force a rule update from upstream sources",
		Long:  "Instructs the agent to immediately pull the latest detection rules from configured upstream sources (Sigma repositories, YARA rule feeds, IOC databases).",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := agentRequest("POST", "/api/v1/rules/update", nil)
			if err != nil {
				return fmt.Errorf("rules update failed: %w", err)
			}
			return printActionResult(body)
		},
	}

	parent.AddCommand(updateCmd)
	return parent
}

// ---------- config ----------

// newConfigCmd returns the config parent command with subcommands for
// viewing the agent's current configuration.
func newConfigCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "config",
		Short: "Agent configuration management",
		Long:  "Commands for viewing and managing the agent's configuration.",
	}

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Display current agent config (secrets masked)",
		Long:  "Reads and displays the current agent configuration file. Sensitive values such as API keys, secrets, and credentials are automatically masked in the output.",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(configFile)
			if err != nil {
				return fmt.Errorf("reading config %s: %w", configFile, err)
			}

			var raw map[string]interface{}
			if err := yaml.Unmarshal(data, &raw); err != nil {
				return fmt.Errorf("parsing config: %w", err)
			}

			maskSecrets(raw)

			out, err := yaml.Marshal(raw)
			if err != nil {
				return fmt.Errorf("formatting config: %w", err)
			}

			fmt.Printf("# Config: %s\n# Secrets masked with ********\n\n%s", configFile, string(out))
			return nil
		},
	}

	parent.AddCommand(showCmd)
	return parent
}

// ---------- version ----------

// newVersionCmd returns the version command that displays build information.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print edrctl version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("edrctl %s\n  commit:  %s\n  built:   %s\n  go:      %s\n  os/arch: %s/%s\n",
				version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
}

// ---------- helpers ----------

// agentRequest sends an HTTP request to the agent's control interface, trying
// the Unix domain socket first and falling back to the HTTP endpoint.
func agentRequest(method, path string, payload []byte) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	if _, err := os.Stat(socketPath); err == nil {
		client.Transport = &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", socketPath, 5*time.Second)
			},
		}
	}

	url := httpAddr + path
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = strings.NewReader(string(payload))
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("agent returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

// printActionResult decodes a standard agent action response and prints
// the result to stdout.
func printActionResult(body []byte) error {
	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Action  string `json:"action"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println(string(body))
		return nil
	}

	status := "FAILED"
	if result.Success {
		status = "OK"
	}
	fmt.Printf("[%s] %s", status, result.Message)
	if result.Action != "" {
		fmt.Printf(" (action: %s)", result.Action)
	}
	fmt.Println()
	return nil
}

// severityAtLeast returns true if sev is at or above the given minimum
// in the severity ordering: info < low < medium < high < critical.
func severityAtLeast(sev, minimum string) bool {
	order := map[string]int{
		"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
	}
	return order[strings.ToLower(sev)] >= order[strings.ToLower(minimum)]
}

// maskSecrets recursively walks a YAML map and replaces values whose keys
// contain sensitive substrings with a masked placeholder.
func maskSecrets(m map[string]interface{}) {
	sensitiveKeys := []string{"key", "secret", "password", "token", "credential"}
	for k, v := range m {
		lower := strings.ToLower(k)
		isSensitive := false
		for _, s := range sensitiveKeys {
			if strings.Contains(lower, s) {
				isSensitive = true
				break
			}
		}

		switch val := v.(type) {
		case map[string]interface{}:
			maskSecrets(val)
		case string:
			if isSensitive && val != "" {
				m[k] = "********"
			}
		}
	}
}

// truncate shortens s to maxLen characters, appending an ellipsis if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
