package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFleetConfigPeek(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(`
agent:
  id: agent-123
  data_dir: /var/lib/edr-agent
server:
  endpoint: cp.example.com
  grpc_port: 50051
  mutual_tls: true
  tls_cert: /etc/edr-agent/tls/agent-client.crt
  ca_cert: /etc/edr-agent/tls/ca.crt
`), 0o644); err != nil {
		t.Fatal(err)
	}
	peek, err := readFleetConfigPeek(path)
	if err != nil {
		t.Fatal(err)
	}
	if peek.Agent.ID != "agent-123" {
		t.Fatalf("agent id = %q", peek.Agent.ID)
	}
	if peek.Server.Endpoint != "cp.example.com" {
		t.Fatalf("endpoint = %q", peek.Server.Endpoint)
	}
	if !peek.Server.MutualTLS {
		t.Fatal("expected mutual_tls true")
	}
}
