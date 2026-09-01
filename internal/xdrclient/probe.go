package xdrclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// LocalEnrollment is what the operator UI can prove from disk without root
// or Keychain access. Used when `edrctl ui` runs as the console user.
type LocalEnrollment struct {
	Enrolled   bool
	AgentID    string
	MachineID  string
	Ingest     string
	CertExpiry string
}

type diskEnrollMeta struct {
	AgentID      string    `json:"agent_id"`
	MachineID    string    `json:"machine_id"`
	IngestHosts  []string  `json:"ingest_hosts"`
	CertNotAfter time.Time `json:"cert_not_after"`
}

// ProbeLocalEnrollment looks at enrollment.json and sealed cert files under
// the agent data dir. A present-but-unreadable sidecar still counts as enrolled
// (root writes 0600 files the GUI user cannot open).
func ProbeLocalEnrollment(configPath, dataDir string) LocalEnrollment {
	var dirs []string
	add := func(d string) {
		d = strings.TrimSpace(d)
		if d == "" {
			return
		}
		for _, e := range dirs {
			if e == d {
				return
			}
		}
		dirs = append(dirs, d)
	}
	add(peekYAMLDataDir(configPath))
	add(dataDir)
	for _, dir := range dirs {
		if hint := probeEnrollmentDir(dir); hint.Enrolled {
			return hint
		}
	}
	return LocalEnrollment{}
}

func peekYAMLDataDir(configPath string) string {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	var peek struct {
		Agent struct {
			DataDir string `yaml:"data_dir"`
		} `yaml:"agent"`
	}
	_ = yaml.Unmarshal(raw, &peek)
	return strings.TrimSpace(peek.Agent.DataDir)
}

func probeEnrollmentDir(dataDir string) LocalEnrollment {
	tls := filepath.Join(dataDir, "xdr-tls")
	path := filepath.Join(tls, "enrollment.json")
	if raw, err := os.ReadFile(path); err == nil {
		var meta diskEnrollMeta
		if json.Unmarshal(raw, &meta) == nil {
			id := strings.TrimSpace(meta.AgentID)
			if id != "" || len(meta.IngestHosts) > 0 {
				out := LocalEnrollment{
					Enrolled:  true,
					AgentID:   id,
					MachineID: strings.TrimSpace(meta.MachineID),
					Ingest:    strings.Join(meta.IngestHosts, ","),
				}
				if !meta.CertNotAfter.IsZero() {
					out.CertExpiry = meta.CertNotAfter.UTC().Format(time.RFC3339)
				}
				return out
			}
		}
		return LocalEnrollment{Enrolled: true}
	} else if isDenied(err) {
		return LocalEnrollment{Enrolled: true}
	}
	if _, err := os.Stat(path); err == nil || isDenied(err) {
		return LocalEnrollment{Enrolled: true}
	}
	for _, name := range []string{"agent.crt.enc", "agent.key.enc", "agent.crt", "ingest.status", "ca-chain.pem"} {
		p := filepath.Join(tls, name)
		if _, err := os.Stat(p); err == nil || isDenied(err) {
			return LocalEnrollment{Enrolled: true}
		}
	}
	if st, err := os.Stat(tls); err == nil && st.IsDir() {
		if _, err := os.ReadDir(tls); isDenied(err) {
			return LocalEnrollment{Enrolled: true}
		}
	} else if isDenied(err) {
		return LocalEnrollment{Enrolled: true}
	}
	return LocalEnrollment{}
}

func isDenied(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "permission denied")
}
