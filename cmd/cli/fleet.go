package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type fleetConfigPeek struct {
	Agent struct {
		ID      string `yaml:"id"`
		DataDir string `yaml:"data_dir"`
	} `yaml:"agent"`
	Server struct {
		Endpoint    string `yaml:"endpoint"`
		GRPCPort    int    `yaml:"grpc_port"`
		MutualTLS   bool   `yaml:"mutual_tls"`
		TLSCertPath string `yaml:"tls_cert"`
		CACertPath  string `yaml:"ca_cert"`
	} `yaml:"server"`
}

func newFleetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Fleet control plane enrollment visibility",
	}
	cmd.AddCommand(newFleetLocalCmd(), newFleetCheckCmd(), newFleetAgentsCmd(), newFleetAlertsCmd(), newFleetPolicyCmd())
	return cmd
}

func newFleetLocalCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "local",
		Short: "Show local fleet endpoint settings from agent config",
		RunE: func(cmd *cobra.Command, args []string) error {
			peek, err := readFleetConfigPeek(configFile)
			if err != nil {
				return err
			}
			return printFleetLocal(os.Stdout, peek)
		},
	}
}

func newFleetCheckCmd() *cobra.Command {
	var (
		host    string
		port    int
		https   bool
		token   string
		caCert  string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Verify local agent enrollment on the control plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			peek, err := readFleetConfigPeek(configFile)
			if err != nil {
				return err
			}
			if err := printFleetLocal(os.Stdout, peek); err != nil {
				return err
			}
			agentID := resolveLocalAgentID(peek)
			if agentID == "" {
				return fmt.Errorf("local agent_id is not configured")
			}
			resolvedHost, err := resolveFleetHost(host)
			if err != nil {
				return err
			}
			scheme := "http"
			if https {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://%s:%d/v1/agents", scheme, resolvedHost, port)
			client, err := fleetHTTPClient(https, resolveFleetCACert(caCert), timeout)
			if err != nil {
				return err
			}
			body, err := fleetHTTPGet(url, token, client)
			if err != nil {
				return err
			}
			var payload struct {
				Agents []struct {
					AgentID       string    `json:"agent_id"`
					Hostname      string    `json:"hostname"`
					OS            string    `json:"os"`
					Version       string    `json:"version"`
					LastHeartbeat time.Time `json:"last_heartbeat"`
					LastStatus    string    `json:"last_status"`
				} `json:"agents"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				return fmt.Errorf("parsing agents response: %w", err)
			}
			for _, agent := range payload.Agents {
				if agent.AgentID != agentID {
					continue
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w)
				fmt.Fprintf(w, "CP Enrolled:\ttrue\n")
				fmt.Fprintf(w, "CP Hostname:\t%s\n", agent.Hostname)
				fmt.Fprintf(w, "CP Last Heartbeat:\t%s\n", agent.LastHeartbeat.UTC().Format(time.RFC3339))
				fmt.Fprintf(w, "CP Status:\t%s\n", agent.LastStatus)
				return w.Flush()
			}
			return fmt.Errorf("agent %s is not enrolled on control plane %s", agentID, resolvedHost)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "control plane host (defaults to server.endpoint in config)")
	cmd.Flags().IntVar(&port, "port", 8080, "control plane HTTP port")
	cmd.Flags().BoolVar(&https, "https", false, "use HTTPS for control plane HTTP API")
	cmd.Flags().StringVar(&token, "token", os.Getenv("EDR_CONTROLPLANE_API_TOKEN"), "control plane API token")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate path for HTTPS verification")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "HTTP request timeout")
	return cmd
}

func printFleetLocal(w io.Writer, peek fleetConfigPeek) error {
	agentID := resolveLocalAgentID(peek)
	port := peek.Server.GRPCPort
	if port == 0 {
		port = 50051
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Config:\t%s\n", configFile)
	fmt.Fprintf(tw, "Agent ID:\t%s\n", agentID)
	fmt.Fprintf(tw, "Endpoint:\t%s\n", peek.Server.Endpoint)
	fmt.Fprintf(tw, "gRPC Port:\t%d\n", port)
	fmt.Fprintf(tw, "Mutual TLS:\t%v\n", peek.Server.MutualTLS)
	if peek.Server.TLSCertPath != "" {
		fmt.Fprintf(tw, "TLS Cert:\t%s\n", peek.Server.TLSCertPath)
	}
	if peek.Server.CACertPath != "" {
		fmt.Fprintf(tw, "CA Cert:\t%s\n", peek.Server.CACertPath)
	}
	if peek.Agent.DataDir != "" {
		queuePath := filepath.Join(peek.Agent.DataDir, "controlplane-pending-alerts.jsonl")
		if pending, err := countJSONLLines(queuePath); err == nil && pending > 0 {
			fmt.Fprintf(tw, "CP Alert Queue:\t%d pending (%s)\n", pending, queuePath)
		}
	}
	return tw.Flush()
}

func resolveLocalAgentID(peek fleetConfigPeek) string {
	agentID := strings.TrimSpace(peek.Agent.ID)
	if agentID == "" && peek.Agent.DataDir != "" {
		idPath := filepath.Join(peek.Agent.DataDir, "agent_id")
		if data, err := os.ReadFile(idPath); err == nil {
			agentID = strings.TrimSpace(string(data))
		}
	}
	return agentID
}

func newFleetAgentsCmd() *cobra.Command {
	var (
		host    string
		port    int
		https   bool
		token   string
		caCert  string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "List agents enrolled on the control plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedHost, err := resolveFleetHost(host)
			if err != nil {
				return err
			}
			scheme := "http"
			if https {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://%s:%d/v1/agents", scheme, resolvedHost, port)
			client, err := fleetHTTPClient(https, resolveFleetCACert(caCert), timeout)
			if err != nil {
				return err
			}
			body, err := fleetHTTPGet(url, token, client)
			if err != nil {
				return err
			}
			var payload struct {
				Agents []struct {
					AgentID       string    `json:"agent_id"`
					Hostname      string    `json:"hostname"`
					OS            string    `json:"os"`
					Version       string    `json:"version"`
					PolicyHash    string    `json:"policy_hash"`
					LastHeartbeat time.Time `json:"last_heartbeat"`
					LastStatus    string    `json:"last_status"`
				} `json:"agents"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				return fmt.Errorf("parsing agents response: %w", err)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "AGENT ID\tHOSTNAME\tOS\tPOLICY\tVERSION\tLAST HEARTBEAT\tSTATUS")
			for _, agent := range payload.Agents {
				policy := agent.PolicyHash
				if len(policy) > 12 {
					policy = policy[:12] + "..."
				}
				if policy == "" {
					policy = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					agent.AgentID,
					agent.Hostname,
					agent.OS,
					policy,
					agent.Version,
					agent.LastHeartbeat.UTC().Format(time.RFC3339),
					agent.LastStatus,
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "control plane host (defaults to server.endpoint in config)")
	cmd.Flags().IntVar(&port, "port", 8080, "control plane HTTP port")
	cmd.Flags().BoolVar(&https, "https", false, "use HTTPS for control plane HTTP API")
	cmd.Flags().StringVar(&token, "token", os.Getenv("EDR_CONTROLPLANE_API_TOKEN"), "control plane API token")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate path for HTTPS verification")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "HTTP request timeout")
	return cmd
}

func newFleetAlertsCmd() *cobra.Command {
	var (
		host    string
		port    int
		https   bool
		token   string
		caCert  string
		limit   int
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "List recent alerts ingested by the control plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedHost, err := resolveFleetHost(host)
			if err != nil {
				return err
			}
			scheme := "http"
			if https {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://%s:%d/v1/alerts?limit=%d", scheme, resolvedHost, port, limit)
			client, err := fleetHTTPClient(https, resolveFleetCACert(caCert), timeout)
			if err != nil {
				return err
			}
			body, err := fleetHTTPGet(url, token, client)
			if err != nil {
				return err
			}
			var payload struct {
				Alerts []map[string]any `json:"alerts"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				return fmt.Errorf("parsing alerts response: %w", err)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "RECEIVED\tALERT ID\tAGENT ID\tRULE ID\tSEVERITY\tTITLE")
			for _, alert := range payload.Alerts {
				fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\t%v\n",
					alert["received_at"],
					alert["alert_id"],
					alert["agent_id"],
					alert["rule_id"],
					alert["severity"],
					alert["title"],
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "control plane host (defaults to server.endpoint in config)")
	cmd.Flags().IntVar(&port, "port", 8080, "control plane HTTP port")
	cmd.Flags().BoolVar(&https, "https", false, "use HTTPS for control plane HTTP API")
	cmd.Flags().StringVar(&token, "token", os.Getenv("EDR_CONTROLPLANE_API_TOKEN"), "control plane API token")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate path for HTTPS verification")
	cmd.Flags().IntVar(&limit, "limit", 20, "maximum alerts to return")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "HTTP request timeout")
	return cmd
}

func newFleetPolicyCmd() *cobra.Command {
	var (
		host    string
		port    int
		https   bool
		token   string
		caCert  string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Show detection rule bundles published by the control plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedHost, err := resolveFleetHost(host)
			if err != nil {
				return err
			}
			scheme := "http"
			if https {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://%s:%d/v1/policy", scheme, resolvedHost, port)
			client, err := fleetHTTPClient(https, resolveFleetCACert(caCert), timeout)
			if err != nil {
				return err
			}
			body, err := fleetHTTPGet(url, token, client)
			if err != nil {
				return err
			}
			var payload struct {
				PolicyHash string `json:"policy_hash"`
				Bundles    []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Format  string `json:"format"`
					Hash    string `json:"hash"`
				} `json:"bundles"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				return fmt.Errorf("parsing policy response: %w", err)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Policy Hash:\t%s\n", payload.PolicyHash)
			fmt.Fprintln(w, "NAME\tVERSION\tFORMAT\tHASH")
			for _, bundle := range payload.Bundles {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					bundle.Name,
					bundle.Version,
					bundle.Format,
					bundle.Hash,
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "control plane host (defaults to server.endpoint in config)")
	cmd.Flags().IntVar(&port, "port", 8080, "control plane HTTP port")
	cmd.Flags().BoolVar(&https, "https", false, "use HTTPS for control plane HTTP API")
	cmd.Flags().StringVar(&token, "token", os.Getenv("EDR_CONTROLPLANE_API_TOKEN"), "control plane API token")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate path for HTTPS verification")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "HTTP request timeout")
	return cmd
}

func readFleetConfigPeek(path string) (fleetConfigPeek, error) {
	var peek fleetConfigPeek
	data, err := os.ReadFile(path)
	if err != nil {
		return peek, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &peek); err != nil {
		return peek, fmt.Errorf("parse config: %w", err)
	}
	return peek, nil
}

func countJSONLLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}
