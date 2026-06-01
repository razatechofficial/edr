package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const agentIDFileName = "agent_id"

// EnsureAgentIdentity loads or persists a stable agent ID in data_dir.
func EnsureAgentIdentity(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if strings.TrimSpace(cfg.Agent.DataDir) == "" {
		return fmt.Errorf("agent.data_dir is required for persistent agent identity")
	}
	if err := os.MkdirAll(cfg.Agent.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data_dir: %w", err)
	}

	path := filepath.Join(cfg.Agent.DataDir, agentIDFileName)
	if id := strings.TrimSpace(cfg.Agent.ID); id != "" {
		return writeAgentID(path, id)
	}
	if data, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			cfg.Agent.ID = id
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read agent_id: %w", err)
	}

	id := uuid.NewString()
	cfg.Agent.ID = id
	return writeAgentID(path, id)
}

func writeAgentID(path, id string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// NormalizeServerEndpoint splits host:port in server.endpoint when grpc_port is unset.
func NormalizeServerEndpoint(cfg *Config) {
	if cfg == nil {
		return
	}
	ep := strings.TrimSpace(cfg.Server.Endpoint)
	if ep == "" {
		return
	}
	if !strings.Contains(ep, ":") {
		cfg.Server.Endpoint = ep
		return
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		cfg.Server.Endpoint = ep
		return
	}
	cfg.Server.Endpoint = host
	if cfg.Server.GRPCPort == 0 {
		if port, perr := strconv.Atoi(portStr); perr == nil {
			cfg.Server.GRPCPort = port
		}
	}
}
