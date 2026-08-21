package xdrclient

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/razatechofficial/edr/internal/config"
)

// BootstrapOverrides are CLI/installer inputs layered over config/env.
// Priority for token: FlagToken > cfg.EnrollmentToken > FlagTokenFile/cfg.EnrollmentTokenFile > default paths.
type BootstrapOverrides struct {
	Host      string
	Token     string
	TokenFile string
	// InsecureSkipTLS is applied only when InsecureSet is true.
	InsecureSkipTLS bool
	InsecureSet     bool
	// ConfigDir / DataDir are used to discover default enrollment.token sidecars.
	ConfigDir string
	DataDir   string
}

// BootstrapResult describes where bootstrap material came from (never logs the token).
type BootstrapResult struct {
	TokenFileUsed string // path read for token, if any
	TokenFromFile bool
}

// DefaultEnrollmentTokenPath returns the canonical install-time token sidecar path.
func DefaultEnrollmentTokenPath(configDir string) string {
	configDir = strings.TrimSpace(configDir)
	if configDir == "" {
		return ""
	}
	return filepath.Join(configDir, "enrollment.token")
}

// ApplyBootstrap merges flag/env/file bootstrap credentials into cfg.
func ApplyBootstrap(cfg *config.XDRConfig, ov BootstrapOverrides) (BootstrapResult, error) {
	var res BootstrapResult
	if cfg == nil {
		return res, fmt.Errorf("xdr config is nil")
	}
	if h := strings.TrimSpace(ov.Host); h != "" {
		cfg.EnrollmentHost = h
	}
	if ov.InsecureSet {
		cfg.InsecureSkipTLS = ov.InsecureSkipTLS
	}

	token := strings.TrimSpace(ov.Token)
	tokenFile := strings.TrimSpace(ov.TokenFile)
	if tokenFile == "" {
		tokenFile = strings.TrimSpace(cfg.EnrollmentTokenFile)
	}

	if token == "" {
		token = strings.TrimSpace(cfg.EnrollmentToken)
	}

	if token == "" {
		candidates := make([]string, 0, 4)
		if tokenFile != "" {
			candidates = append(candidates, tokenFile)
		}
		if p := DefaultEnrollmentTokenPath(ov.ConfigDir); p != "" {
			candidates = append(candidates, p)
		}
		if d := strings.TrimSpace(ov.DataDir); d != "" {
			candidates = append(candidates, filepath.Join(d, "enrollment.token"))
		}
		if cfgDir := strings.TrimSpace(ov.ConfigDir); cfgDir != "" {
			candidates = append(candidates, filepath.Join(cfgDir, "com.razatech.edr.enrollment-token"))
		}
		for _, p := range candidates {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if t := strings.TrimSpace(string(b)); t != "" {
				token = t
				res.TokenFileUsed = p
				res.TokenFromFile = true
				cfg.EnrollmentTokenFile = p
				break
			}
		}
	} else if tokenFile != "" {
		// Token provided explicitly; still remember file path for post-enroll wipe.
		cfg.EnrollmentTokenFile = tokenFile
		res.TokenFileUsed = tokenFile
	}

	if token != "" {
		cfg.EnrollmentToken = token
	}
	return res, nil
}

// WriteEnrollmentTokenFile writes a root-only bootstrap token sidecar.
func WriteEnrollmentTokenFile(path, token string) error {
	path = strings.TrimSpace(path)
	token = strings.TrimSpace(token)
	if path == "" {
		return fmt.Errorf("enrollment token path required")
	}
	if token == "" {
		return fmt.Errorf("enrollment token required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(token+"\n"), 0o600)
}

// ClearBootstrapMaterial removes one-time enrollment secrets after successful Register.
// It deletes the token file (if any) and clears xdr.enrollment_token in the agent YAML.
func ClearBootstrapMaterial(configPath, tokenFile string) error {
	var first error
	if f := strings.TrimSpace(tokenFile); f != "" {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) && first == nil {
			first = fmt.Errorf("remove token file: %w", err)
		}
	}
	if p := strings.TrimSpace(configPath); p != "" {
		if err := ClearEnrollmentTokenInConfig(p); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// ClearEnrollmentTokenInConfig blanks xdr.enrollment_token in a YAML config file.
func ClearEnrollmentTokenInConfig(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse config for token clear: %w", err)
	}
	doc := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		doc = root.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return nil
	}
	xdr := mapValue(doc, "xdr")
	if xdr == nil {
		return nil
	}
	tok := mapValue(xdr, "enrollment_token")
	if tok == nil || strings.TrimSpace(tok.Value) == "" {
		return nil
	}
	tok.Kind = yaml.ScalarNode
	tok.Tag = "!!str"
	tok.Value = ""
	out, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o640)
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// ShouldInitXDR reports whether the agent should run enrollment/ingest wiring.
func ShouldInitXDR(cfg config.XDRConfig, dataDir string) bool {
	if cfg.EnabledForEnrollment() {
		return true
	}
	store := Store{
		Dir:     resolveCertDir(cfg, dataDir),
		DataDir: dataDir,
		Backend: cfg.SecureStorage,
	}
	return store.HasCredentials()
}

// PatchXDRConfigFile enables XDR settings in agent.yaml without embedding the token.
func PatchXDRConfigFile(path string, host string, insecure bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return err
	}
	doc := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		doc = root.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return fmt.Errorf("config root is not a mapping")
	}
	xdr := mapValue(doc, "xdr")
	if xdr == nil {
		xdr = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Content = append(doc.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "xdr"},
			xdr,
		)
	}
	setMapBool(xdr, "enabled", true)
	if host != "" {
		setMapString(xdr, "enrollment_host", host)
	}
	if host == DefaultEnrollmentHost {
		setMapStringList(xdr, "ingest_hosts", DefaultIngestHosts())
	}
	setMapBool(xdr, "insecure_skip_tls", insecure)
	setMapString(xdr, "secure_storage", "auto")
	setMapString(xdr, "enrollment_token", "")
	out, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o640)
}

func setMapString(m *yaml.Node, key, value string) {
	if n := mapValue(m, key); n != nil {
		n.Kind = yaml.ScalarNode
		n.Tag = "!!str"
		n.Value = value
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	)
}

func setMapBool(m *yaml.Node, key string, value bool) {
	v := "false"
	if value {
		v = "true"
	}
	if n := mapValue(m, key); n != nil {
		n.Kind = yaml.ScalarNode
		n.Tag = "!!bool"
		n.Value = v
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: v},
	)
}

func setMapStringList(m *yaml.Node, key string, values []string) {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range values {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
	}
	if n := mapValue(m, key); n != nil {
		*n = *seq
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		seq,
	)
}
