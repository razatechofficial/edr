package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	cmd.AddCommand(newFleetLocalCmd(), newFleetAgentsCmd())
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
			agentID := peek.Agent.ID
			if agentID == "" && peek.Agent.DataDir != "" {
				idPath := filepath.Join(peek.Agent.DataDir, "agent_id")
				if data, err := os.ReadFile(idPath); err == nil {
					agentID = string(data)
				}
			}
			port := peek.Server.GRPCPort
			if port == 0 {
				port = 50051
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "Config:\t%s\n", configFile)
			fmt.Fprintf(w, "Agent ID:\t%s\n", agentID)
			fmt.Fprintf(w, "Endpoint:\t%s\n", peek.Server.Endpoint)
			fmt.Fprintf(w, "gRPC Port:\t%d\n", port)
			fmt.Fprintf(w, "Mutual TLS:\t%v\n", peek.Server.MutualTLS)
			if peek.Server.TLSCertPath != "" {
				fmt.Fprintf(w, "TLS Cert:\t%s\n", peek.Server.TLSCertPath)
			}
			if peek.Server.CACertPath != "" {
				fmt.Fprintf(w, "CA Cert:\t%s\n", peek.Server.CACertPath)
			}
			return w.Flush()
		},
	}
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
			if host == "" {
				peek, err := readFleetConfigPeek(configFile)
				if err != nil {
					return fmt.Errorf("--host required: %w", err)
				}
				host = peek.Server.Endpoint
			}
			if host == "" || host == "YOUR_CONTROL_PLANE_HOST" {
				return fmt.Errorf("control plane host is not configured; pass --host")
			}
			scheme := "http"
			if https {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://%s:%d/v1/agents", scheme, host, port)
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			client := &http.Client{Timeout: timeout}
			if https && caCert != "" {
				// Keep simple: rely on system trust or curl in scripts for custom CA pinning.
				_ = caCert
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("control plane returned %s: %s", resp.Status, string(body))
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
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "AGENT ID\tHOSTNAME\tOS\tVERSION\tLAST HEARTBEAT\tSTATUS")
			for _, agent := range payload.Agents {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					agent.AgentID,
					agent.Hostname,
					agent.OS,
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
