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
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Operator dashboard (status, enrollment, detections)",
		Long:  "Prints a compact operator dashboard. Use --json for the GUI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := collectOperatorStatus(!asJSON)
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}
			return printOperatorDashboard(os.Stdout, st)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON for the operator GUI")
	return cmd
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

type operatorHostProbe struct {
	Host   string `json:"host"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type operatorStatus struct {
	Config     string              `json:"config"`
	Service    string              `json:"service"`
	Enrolled   bool                `json:"enrolled"`
	AgentID    string              `json:"agent_id,omitempty"`
	MachineID  string              `json:"machine_id,omitempty"`
	Ingest     string              `json:"ingest,omitempty"`
	Runtime    string              `json:"runtime,omitempty"`
	Version    string              `json:"version,omitempty"`
	Uptime     string              `json:"uptime,omitempty"`
	Detections uint64              `json:"detections"`
	EventsProc uint64              `json:"events_processed,omitempty"`
	Blocks     uint64              `json:"blocks,omitempty"`
	RulesCount int                 `json:"rules_count,omitempty"`
	SpoolBytes int64               `json:"spool_bytes,omitempty"`
	CertExpiry string              `json:"cert_not_after,omitempty"`
	CPUPercent float64             `json:"cpu_percent,omitempty"`
	MemoryMB   float64             `json:"memory_mb,omitempty"`
	Isolated         bool                `json:"isolated"`
	ControlAPI       string              `json:"control_api"`
	IngestConfigured bool                `json:"ingest_configured"`
	IngestEnv        bool                `json:"ingest_env"`
	IngestOK         bool                `json:"ingest_ok"`
	IngestFault      string              `json:"ingest_fault,omitempty"`
	Hosts            []operatorHostProbe `json:"hosts,omitempty"`
	UpdatedAt        string              `json:"updated_at"`
}

func collectOperatorStatus(probeHosts bool) operatorStatus {
	st := operatorStatus{
		Config:     configFile,
		Service:    serviceRuntimeStatus(),
		ControlAPI: "unavailable",
		UpdatedAt:  time.Now().Format(time.RFC3339),
	}
	st.Enrolled, st.AgentID, st.Ingest = enrollmentSnapshot()
	st.MachineID, st.CertExpiry = enrollmentIdentity()
	st.SpoolBytes = dirSize(filepath.Join(peekDataDir(), "telemetry-queue"))
	st.Blocks = countFiles(filepath.Join(peekDataDir(), "quarantine"))
	st.IngestConfigured = xdrIngestConfigured()
	st.IngestEnv = xdrRuntimeEnvEnabled()
	st.IngestOK = ingestStreamLive()
	st.IngestFault = ingestStreamFault()

	body, err := agentRequest("GET", "/api/v1/status", nil)
	if err == nil {
		st.ControlAPI = "ok"
		var status struct {
			Status     string  `json:"status"`
			Version    string  `json:"version"`
			Uptime     string  `json:"uptime"`
			AlertsGen  uint64  `json:"alerts_generated"`
			Isolated   bool    `json:"isolated"`
			CPUPercent float64 `json:"cpu_percent"`
			MemoryMB   float64 `json:"memory_mb"`
			EventsProc uint64  `json:"events_processed"`
			RulesCount int     `json:"rules_count"`
		}
		if json.Unmarshal(body, &status) == nil {
			st.Runtime = status.Status
			st.Version = status.Version
			st.Uptime = status.Uptime
			st.Detections = status.AlertsGen
			st.Isolated = status.Isolated
			st.CPUPercent = status.CPUPercent
			st.MemoryMB = status.MemoryMB
			st.EventsProc = status.EventsProc
			st.RulesCount = status.RulesCount
		}
	}

	if !probeHosts {
		return st
	}

	hosts, herr := connectionTargets()
	if herr != nil {
		st.Hosts = []operatorHostProbe{{Host: "-", OK: false, Detail: herr.Error()}}
	} else {
		for _, host := range hosts {
			p := operatorHostProbe{Host: host, OK: true}
			if err := probeTCP(host, 4*time.Second); err != nil {
				p.OK = false
				p.Detail = err.Error()
			}
			st.Hosts = append(st.Hosts, p)
		}
	}
	return st
}

func printOperatorDashboard(out *os.File, st operatorStatus) error {
	fmt.Fprintln(out, "╔══════════════════════════════════════════════════════╗")
	fmt.Fprintln(out, "║                   EDR Agent                          ║")
	fmt.Fprintln(out, "╚══════════════════════════════════════════════════════╝")

	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "Config:\t%s\n", st.Config)
	fmt.Fprintf(w, "Service:\t%s\n", st.Service)
	if st.Enrolled {
		fmt.Fprintf(w, "Enrollment:\tenrolled\n")
		if st.AgentID != "" {
			fmt.Fprintf(w, "Agent ID:\t%s\n", st.AgentID)
		}
		if st.Ingest != "" {
			fmt.Fprintf(w, "Ingest:\t%s\n", st.Ingest)
		}
	} else {
		fmt.Fprintf(w, "Enrollment:\tidle (not enrolled)\n")
		fmt.Fprintln(w, "Next:\tedrctl enroll --token <token>")
	}
	if st.ControlAPI != "ok" {
		fmt.Fprintf(w, "Control API:\tunavailable\n")
		fmt.Fprintf(w, "Detections:\tn/a (agent not responding)\n")
		fmt.Fprintf(w, "Blocks:\tn/a\n")
	} else {
		fmt.Fprintf(w, "Runtime:\t%s\n", emptyDash(st.Runtime))
		fmt.Fprintf(w, "Version:\t%s\n", emptyDash(st.Version))
		fmt.Fprintf(w, "Uptime:\t%s\n", emptyDash(st.Uptime))
		fmt.Fprintf(w, "Local detections:\t%d\n", st.Detections)
		fmt.Fprintf(w, "Events processed:\t%d\n", st.EventsProc)
		fmt.Fprintf(w, "Agent CPU:\t%.1f%%\n", st.CPUPercent)
		fmt.Fprintf(w, "Agent memory:\t%.1f MB\n", st.MemoryMB)
		if st.Isolated {
			fmt.Fprintf(w, "Containment:\tISOLATED\n")
		} else {
			fmt.Fprintf(w, "Containment:\tnormal\n")
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Connection test")
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tRESULT")
	for _, h := range st.Hosts {
		if h.OK {
			fmt.Fprintf(tw, "%s\tok\n", h.Host)
		} else if h.Detail != "" {
			fmt.Fprintf(tw, "%s\tfail (%s)\n", h.Host, h.Detail)
		} else {
			fmt.Fprintf(tw, "%s\tfail\n", h.Host)
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
	AgentID       string    `json:"agent_id"`
	MachineID     string    `json:"machine_id"`
	IngestHosts   []string  `json:"ingest_hosts"`
	CertNotAfter  time.Time `json:"cert_not_after"`
	SecureStorage string    `json:"secure_storage"`
}

func peekDataDir() string {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return ""
	}
	var peek yamlConfigPeek
	_ = yaml.Unmarshal(data, &peek)
	return peek.Agent.DataDir
}

func enrollmentIdentity() (machineID, certExpiry string) {
	dir := peekDataDir()
	if dir == "" {
		return "", ""
	}
	raw, err := os.ReadFile(filepath.Join(dir, "xdr-tls", "enrollment.json"))
	if err != nil {
		return "", ""
	}
	var meta enrollMeta
	if json.Unmarshal(raw, &meta) != nil {
		return "", ""
	}
	if !meta.CertNotAfter.IsZero() {
		certExpiry = meta.CertNotAfter.UTC().Format(time.RFC3339)
	}
	return meta.MachineID, certExpiry
}

func dirSize(root string) int64 {
	var n int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		n += info.Size()
		return nil
	})
	return n
}

func countFiles(root string) uint64 {
	var n uint64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		n++
		return nil
	})
	return n
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
		return false, "", ""
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "xdr-tls", "enrollment.json"))
	if err != nil {
		// Installer Agent.ID is not enrollment. Missing/unreadable json = not enrolled
		// (common when the GUI user cannot read a root-only 0600 sidecar).
		return false, "", ""
	}
	var meta enrollMeta
	if json.Unmarshal(raw, &meta) != nil {
		return false, "", ""
	}
	ingest = strings.Join(meta.IngestHosts, ",")
	id := meta.AgentID
	if id == "" {
		id = peek.Agent.ID
	}
	return id != "", id, ingest
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

func xdrRuntimeEnvEnabled() bool {
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(configFile), ".env"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "XDR_ENABLED=true" || strings.HasPrefix(line, "XDR_ENABLED=true") {
			return true
		}
	}
	return false
}

func xdrIngestConfigured() bool {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return false
	}
	var cfg struct {
		XDR struct {
			Enabled     bool     `yaml:"enabled"`
			IngestHosts []string `yaml:"ingest_hosts"`
		} `yaml:"xdr"`
	}
	if yaml.Unmarshal(data, &cfg) != nil {
		return false
	}
	if cfg.XDR.Enabled {
		return true
	}
	return len(cfg.XDR.IngestHosts) > 0
}

func ingestStreamLive() bool {
	st, ok := readIngestStatus()
	return ok && st.OK
}

func ingestStreamFault() string {
	st, ok := readIngestStatus()
	if !ok {
		return ""
	}
	return strings.TrimSpace(st.Detail)
}

type ingestStatusFile struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func readIngestStatus() (ingestStatusFile, bool) {
	raw, err := os.ReadFile(filepath.Join(peekDataDir(), "xdr-tls", "ingest.status"))
	if err != nil {
		return ingestStatusFile{}, false
	}
	var st ingestStatusFile
	if json.Unmarshal(raw, &st) != nil {
		return ingestStatusFile{}, false
	}
	return st, true
}

func ingestReachable(ingestCSV string) bool {
	var hosts []string
	for _, h := range strings.Split(ingestCSV, ",") {
		if t := strings.TrimSpace(h); t != "" {
			hosts = append(hosts, t)
		}
	}
	if len(hosts) == 0 {
		data, err := os.ReadFile(configFile)
		if err == nil {
			var cfg struct {
				XDR struct {
					IngestHosts []string `yaml:"ingest_hosts"`
				} `yaml:"xdr"`
			}
			if yaml.Unmarshal(data, &cfg) == nil {
				hosts = append(hosts, cfg.XDR.IngestHosts...)
			}
		}
	}
	if len(hosts) == 0 {
		hosts = []string{xdrclient.DefaultIngestHost}
	}
	for _, h := range hosts {
		if err := probeTCP(h, 3*time.Second); err == nil {
			return true
		}
	}
	return false
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
