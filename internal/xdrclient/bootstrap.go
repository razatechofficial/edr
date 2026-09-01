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
	return writeWorldReadableYAML(path, out)
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
	return writeWorldReadableYAML(path, out)
}

// EnableIngestFromEnrollment writes xdr.enabled + ingest_hosts so the sensor
// starts the ingest relay. Creates the xdr: section if the install YAML never
// had one. Does not embed enrollment tokens.
func EnableIngestFromEnrollment(path string, st State) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("config path required")
	}
	root, doc, err := parseYAMLMapping(path)
	if err != nil {
		return err
	}
	xdr := ensureXDRMap(doc)
	host := DefaultEnrollmentHost
	if n := mapValue(xdr, "enrollment_host"); n != nil {
		if h := strings.TrimSpace(n.Value); h != "" {
			host = h
		}
	}
	ingest := append([]string(nil), st.IngestHosts...)
	if len(ingest) == 0 {
		ingest = DefaultIngestHosts()
	}
	backend := strings.TrimSpace(st.SecureStorage)
	switch backend {
	case "", "auto", "keychain":
		// LaunchDaemon / SYSTEM cannot read a user login Keychain.
		backend = "file"
	}
	setMapBool(xdr, "enabled", true)
	setMapString(xdr, "enrollment_host", host)
	setMapStringList(xdr, "ingest_hosts", ingest)
	setMapString(xdr, "secure_storage", backend)
	setMapString(xdr, "enrollment_token", "")
	if err := writeYAMLRoot(path, root, 0o644); err != nil {
		return err
	}
	return WriteXDRRuntimeEnv(filepath.Dir(path), true, backend)
}

// WriteXDRRuntimeEnv merges XDR_ENABLED / XDR_SECURE_STORAGE into configDir/.env
// so launchd loads them. Viper BindEnv otherwise treats unset XDR_ENABLED as
// false and ignores xdr.enabled in YAML.
func WriteXDRRuntimeEnv(configDir string, enabled bool, backend string) error {
	configDir = strings.TrimSpace(configDir)
	if configDir == "" {
		return fmt.Errorf("config dir required")
	}
	backend = strings.TrimSpace(backend)
	if backend == "" {
		backend = "file"
	}
	path := filepath.Join(configDir, ".env")
	kv := map[string]string{}
	if raw, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if enabled {
		kv["XDR_ENABLED"] = "true"
	} else {
		kv["XDR_ENABLED"] = "false"
	}
	kv["XDR_SECURE_STORAGE"] = backend
	var b strings.Builder
	for _, k := range []string{"XDR_ENABLED", "XDR_SECURE_STORAGE"} {
		if v, ok := kv[k]; ok {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(v)
			b.WriteByte('\n')
			delete(kv, k)
		}
	}
	for k, v := range kv {
		if k == "" {
			continue
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// PinSecureStorage sets xdr.secure_storage without touching enrollment tokens.
func PinSecureStorage(path, backend string) error {
	root, doc, err := parseYAMLMapping(path)
	if err != nil {
		return err
	}
	xdr := ensureXDRMap(doc)
	setMapString(xdr, "secure_storage", strings.TrimSpace(backend))
	return writeYAMLRoot(path, root, 0o644)
}

func parseYAMLMapping(path string) (*yaml.Node, *yaml.Node, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, nil, err
	}
	doc := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		doc = root.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("config root is not a mapping")
	}
	return &root, doc, nil
}

func ensureXDRMap(doc *yaml.Node) *yaml.Node {
	xdr := mapValue(doc, "xdr")
	if xdr != nil {
		return xdr
	}
	xdr = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	doc.Content = append(doc.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "xdr"},
		xdr,
	)
	return xdr
}

func writeYAMLRoot(path string, root *yaml.Node, perm os.FileMode) error {
	out, err := yaml.Marshal(root)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, perm); err != nil {
		return err
	}
	if perm != 0 {
		_ = os.Chmod(path, perm)
	}
	return nil
}

// writeWorldReadableYAML writes agent.yaml so the local console user can read
// enrollment status. os.WriteFile does not change the mode of an existing 0640 file.
func writeWorldReadableYAML(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
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
