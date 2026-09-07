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

// ProbeLocalEnrollment looks at enrollment.json and device cert blobs.
// An empty or ACL-locked xdr-tls folder is not enrollment — Windows MSI
// creates that directory and then denies Users, which used to skip Enroll.
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
	for _, path := range []string{
		filepath.Join(tls, "enrollment.json"),
		filepath.Join(dataDir, "enrollment.json"),
	} {
		if hint := probeEnrollmentJSON(path); hint.Enrolled {
			return hint
		}
	}
	if hasDeviceCertPair(tls) {
		return LocalEnrollment{Enrolled: true}
	}
	return LocalEnrollment{}
}

func probeEnrollmentJSON(path string) LocalEnrollment {
	raw, err := os.ReadFile(path)
	if err != nil {
		if isDenied(err) {
			if _, serr := os.Stat(path); serr == nil {
				return LocalEnrollment{Enrolled: true}
			}
		}
		return LocalEnrollment{}
	}
	var meta diskEnrollMeta
	if json.Unmarshal(raw, &meta) != nil {
		return LocalEnrollment{}
	}
	id := strings.TrimSpace(meta.AgentID)
	if id == "" && len(meta.IngestHosts) == 0 {
		return LocalEnrollment{}
	}
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

func hasDeviceCertPair(tls string) bool {
	cert := fileExists(tls, "agent.crt.dpapi") || fileExists(tls, "agent.crt.enc") || fileExists(tls, "agent.crt")
	key := fileExists(tls, "agent.key.dpapi") || fileExists(tls, "agent.key.enc") || fileExists(tls, "agent.key")
	return cert && key
}

func fileExists(dir, name string) bool {
	st, err := os.Stat(filepath.Join(dir, name))
	return err == nil && !st.IsDir()
}

func isDenied(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "permission denied") ||
		strings.Contains(strings.ToLower(err.Error()), "access is denied")
}
