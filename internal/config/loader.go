package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	mapstructure "github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Load reads configuration from the given file path (YAML, TOML, or JSON),
// overlays environment variables, applies defaults, migrates legacy fields,
// and validates the result. The priority order is:
// environment variables > .env file > config file > Defaults().
func Load(path string) (Config, error) {
	cfg := Defaults()

	v := viper.New()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return Config{}, fmt.Errorf("reading config %s: %w", path, err)
	}

	loadDotEnv(filepath.Dir(path))
	bindEnvVars(v, "", reflect.TypeOf(Config{}))

	if err := v.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
		dc.TagName = "yaml"
	}); err != nil {
		return Config{}, fmt.Errorf("decoding config: %w", err)
	}

	migrateLegacy(&cfg, v)
	applyResourcePathDefaults(&cfg, path)
	applyPerformanceDefaults(&cfg)
	applyDarwinDataDirDefault(&cfg)
	applyLoggingPathDefaults(&cfg)
	ApplyComplianceDefaults(&cfg)

	if err := Validate(&cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// LoadEncrypted decrypts an AES-256-GCM encrypted configuration file using
// the provided key, then loads it identically to Load. The decrypted content
// is expected to be valid YAML.
func LoadEncrypted(path string, key []byte) (Config, error) {
	cfg := Defaults()

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading encrypted config %s: %w", path, err)
	}

	plaintext, err := DecryptConfig(ciphertext, key)
	if err != nil {
		return Config{}, fmt.Errorf("decrypting config: %w", err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(plaintext)); err != nil {
		return Config{}, fmt.Errorf("parsing decrypted config: %w", err)
	}

	loadDotEnv(filepath.Dir(path))
	bindEnvVars(v, "", reflect.TypeOf(Config{}))

	if err := v.Unmarshal(&cfg, func(dc *mapstructure.DecoderConfig) {
		dc.TagName = "yaml"
	}); err != nil {
		return Config{}, fmt.Errorf("decoding config: %w", err)
	}

	migrateLegacy(&cfg, v)
	applyResourcePathDefaults(&cfg, path)
	applyPerformanceDefaults(&cfg)
	applyDarwinDataDirDefault(&cfg)
	applyLoggingPathDefaults(&cfg)
	ApplyComplianceDefaults(&cfg)

	if err := Validate(&cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// LoadSigned loads configuration from a YAML file and verifies an Ed25519
// detached signature at path+".sig" against the public key PEM at pubKeyPath.
// If pubKeyPath is empty, it falls back to unsigned Load.
func LoadSigned(path, pubKeyPath string) (Config, error) {
	if pubKeyPath == "" {
		return Load(path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config %s: %w", path, err)
	}

	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return Config{}, fmt.Errorf("reading config signature %s.sig: %w", path, err)
	}

	pubPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return Config{}, fmt.Errorf("reading config signing key %s: %w", pubKeyPath, err)
	}

	pub, err := parseConfigPubKey(pubPEM)
	if err != nil {
		return Config{}, fmt.Errorf("parsing config signing key: %w", err)
	}

	if !ed25519.Verify(pub, raw, sig) {
		return Config{}, errors.New("config signature verification failed")
	}

	return Load(path)
}

func parseConfigPubKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("config pubkey: invalid PEM")
	}
	raw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("config pubkey: expected Ed25519")
	}
	return pub, nil
}

// loadDotEnv reads a .env file from dir and sets environment variables for
// keys not already present in the environment. This ensures real env vars
// always take precedence over .env file values.
func loadDotEnv(dir string) {
	data, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
}

// bindEnvVars recursively walks the struct type, building Viper key paths from
// yaml struct tags and binding environment variables from env struct tags.
func bindEnvVars(v *viper.Viper, prefix string, t reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		tag := field.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		tag = strings.SplitN(tag, ",", 2)[0]

		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}

		if field.Type.Kind() == reflect.Struct {
			bindEnvVars(v, key, field.Type)
			continue
		}

		if envVar := field.Tag.Get("env"); envVar != "" {
			_ = v.BindEnv(key, envVar)
		}
	}
}

// migrateLegacy copies old-style response.* YAML fields into
// Config.LegacyResponse so that pre-v2 configuration files continue to work.
// It also propagates logging.level to agent.log_level when the new field
// was not explicitly set.
func migrateLegacy(cfg *Config, v *viper.Viper) {
	if v.IsSet("response.allow_kill") {
		cfg.LegacyResponse.AllowKill = v.GetBool("response.allow_kill")
	}
	if v.IsSet("response.auto_kill_enabled") {
		cfg.LegacyResponse.AutoKillEnabled = v.GetBool("response.auto_kill_enabled")
	}
	if v.IsSet("response.min_kill_score") {
		cfg.LegacyResponse.MinKillScore = v.GetInt("response.min_kill_score")
	}
	if v.IsSet("response.kill_rule_allowlist") {
		cfg.LegacyResponse.KillRuleAllowlist = v.GetStringSlice("response.kill_rule_allowlist")
	}
	if v.IsSet("response.protected_processes") {
		cfg.LegacyResponse.ProtectedProcesses = v.GetStringSlice("response.protected_processes")
	}

	if cfg.Logging.Level != "" && !v.IsSet("agent.log_level") {
		cfg.Agent.LogLevel = cfg.Logging.Level
	}
}

// applyPerformanceDefaults maps performance.worker_count <= 0 to runtime.NumCPU()
// (minimum 1), matching shipped agent.yaml comments ("0 = NumCPU").
func applyPerformanceDefaults(cfg *Config) {
	profile := strings.ToLower(strings.TrimSpace(cfg.Performance.Profile))
	if profile == "" {
		profile = "balanced"
	}
	cfg.Performance.Profile = profile

	if cfg.Performance.WorkerCount <= 0 {
		n := runtime.NumCPU()
		if n < 1 {
			n = 1
		}
		cfg.Performance.WorkerCount = n
	}
	switch profile {
	case "low_resource":
		if cfg.Performance.WorkerCount > 1 {
			cfg.Performance.WorkerCount = 1
		}
		if cfg.Performance.EventBufferSize <= 0 || cfg.Performance.EventBufferSize > 2048 {
			cfg.Performance.EventBufferSize = 2048
		}
		if cfg.Performance.BatchSize <= 0 || cfg.Performance.BatchSize > 20 {
			cfg.Performance.BatchSize = 20
		}
		if cfg.Performance.MaxMemoryMB <= 0 || cfg.Performance.MaxMemoryMB > 1024 {
			cfg.Performance.MaxMemoryMB = 512
		}
	case "strict":
		if cfg.Performance.EventBufferSize <= 0 {
			cfg.Performance.EventBufferSize = 8192
		}
		if cfg.Performance.BatchSize <= 0 {
			cfg.Performance.BatchSize = 50
		}
	default: // balanced
		if cfg.Performance.EventBufferSize <= 0 {
			cfg.Performance.EventBufferSize = 4096
		}
		if cfg.Performance.BatchSize <= 0 {
			cfg.Performance.BatchSize = 25
		}
	}
	if strings.TrimSpace(cfg.Logging.Mode) == "" {
		cfg.Logging.Mode = "structured"
	}
}

// applyDarwinDataDirDefault replaces the Linux placeholder data_dir with a
// user-writable path when running on macOS without an explicit override, so
// `go run` and LaunchAgent-style installs work without root.
func applyDarwinDataDirDefault(cfg *Config) {
	if runtime.GOOS != "darwin" {
		return
	}
	if cfg.Agent.DataDir != "/var/lib/edr" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	cfg.Agent.DataDir = filepath.Join(home, "Library", "Application Support", "EDR")
}

// applyLoggingPathDefaults fills empty logging.alert_file / audit_file from
// agent.data_dir (empty paths would otherwise make alert.Writer open "").
func applyLoggingPathDefaults(cfg *Config) {
	dd := cfg.Agent.DataDir
	if dd == "" {
		dd = "/var/lib/edr"
	}
	if cfg.Logging.AlertFile == "" {
		cfg.Logging.AlertFile = filepath.Join(dd, "alerts", "alerts.jsonl")
	}
	if cfg.Logging.AuditFile == "" {
		cfg.Logging.AuditFile = filepath.Join(dd, "audit", "audit.jsonl")
	}
}

// applyResourcePathDefaults resolves empty detection, ML, and rules paths when
// the config file lives next to a standard repo layout (configs/agent.yaml →
// ../rules, ../models) or when Debian-style shipped paths exist under
// /usr/share/edr.
//
// The macOS/Linux installer places bundled rules under <configDir>/rules/
// (e.g. .../Library/Application Support/EDR/config/rules), not only under
// <dataDir>/rules; relative rules_file paths must resolve against the config
// directory first.
func applyResourcePathDefaults(cfg *Config, configPath string) {
	if configPath == "" {
		return
	}
	base := filepath.Dir(configPath)
	// Repo dev: configs/agent.yaml → ../rules; installer: config/agent.yaml → ./rules
	repoRules := filepath.Clean(filepath.Join(base, "..", "rules"))
	configRules := filepath.Join(base, "rules")
	repoModels := filepath.Clean(filepath.Join(base, "..", "models"))

	tryDir := func(path string) bool {
		fi, err := os.Stat(path)
		return err == nil && fi.IsDir()
	}
	tryFile := func(path string) bool {
		fi, err := os.Stat(path)
		return err == nil && !fi.IsDir()
	}

	rulesRoots := []string{configRules, repoRules, "/usr/share/edr/rules"}

	if cfg.Detection.Sigma.Enabled && cfg.Detection.Sigma.RulesDir == "" {
		for _, root := range rulesRoots {
			p := filepath.Join(root, "sigma")
			if tryDir(p) {
				cfg.Detection.Sigma.RulesDir = p
				break
			}
		}
	}
	if cfg.Detection.YARA.Enabled && cfg.Detection.YARA.RulesDir == "" {
		for _, root := range rulesRoots {
			p := filepath.Join(root, "yara")
			if tryDir(p) {
				cfg.Detection.YARA.RulesDir = p
				break
			}
		}
	}
	if cfg.Detection.CustomRules.Enabled && cfg.Detection.CustomRules.RulesPath == "" {
		for _, root := range rulesRoots {
			p := filepath.Join(root, "custom")
			if tryDir(p) || tryFile(p) {
				cfg.Detection.CustomRules.RulesPath = p
				break
			}
		}
		if cfg.Detection.CustomRules.RulesPath == "" {
			for _, root := range rulesRoots {
				sample := filepath.Join(root, "custom", "sample_rules.yaml")
				if tryFile(sample) {
					cfg.Detection.CustomRules.RulesPath = sample
					break
				}
			}
		}
	}
	if cfg.Compliance.Enabled && cfg.Compliance.RulesDir == "" {
		for _, root := range rulesRoots {
			p := filepath.Join(root, "compliance", "sca")
			if tryDir(p) {
				cfg.Compliance.RulesDir = p
				break
			}
		}
	}
	if cfg.Detection.IOC.Enabled {
		resolveIOCPaths(cfg, rulesRoots, tryFile)
	}
	if cfg.ML.Enabled && cfg.ML.ModelsDir == "" {
		for _, p := range []string{
			repoModels,
			"/usr/share/edr/models",
		} {
			if tryDir(p) {
				cfg.ML.ModelsDir = p
				break
			}
		}
	}
	if cfg.LLM.RAG.Enabled && cfg.LLM.RAG.VectorDBPath == "" {
		dd := cfg.Agent.DataDir
		if dd == "" {
			dd = "/var/lib/edr"
		}
		cfg.LLM.RAG.VectorDBPath = filepath.Join(dd, "rag")
	}

	if cfg.RulesFile == "" {
		cfg.RulesFile = "rules/baseline.yaml"
	}
	if !filepath.IsAbs(cfg.RulesFile) {
		// Prefer paths next to the config file (installer: .../config/rules/...) before
		// trusting CWD-relative resolution — launchd has no stable working directory.
		primary := filepath.Clean(filepath.Join(base, cfg.RulesFile))
		if tryFile(primary) {
			cfg.RulesFile = primary
		} else if _, err := os.Stat(cfg.RulesFile); err == nil {
			// Repo layout: configs/agent.yaml + ../rules/baseline.yaml — primary misses, but
			// Stat finds the file relative to process CWD. Freeze to an absolute path so a
			// later open does not depend on CWD (e.g. launchd).
			if abs, err := filepath.Abs(cfg.RulesFile); err == nil {
				cfg.RulesFile = abs
			}
		} else {
			candidates := []string{
				filepath.Clean(filepath.Join(base, "..", cfg.RulesFile)),
				filepath.Join(repoRules, "baseline.yaml"),
				"/usr/share/edr/rules/baseline.yaml",
			}
			for _, p := range candidates {
				if tryFile(p) {
					cfg.RulesFile = p
					break
				}
			}
		}
	}
}

func resolveIOCPaths(cfg *Config, rulesRoots []string, tryFile func(string) bool) {
	type iocFile struct {
		dest *string
		name string
	}
	files := []iocFile{
		{&cfg.Detection.IOC.HashDBPath, "hashes.json"},
		{&cfg.Detection.IOC.IPDBPath, "ips.csv"},
		{&cfg.Detection.IOC.DomainDBPath, "domains.csv"},
	}
	for _, root := range rulesRoots {
		iocDir := filepath.Join(root, "ioc")
		resolved := 0
		for _, f := range files {
			if *f.dest != "" {
				resolved++
				continue
			}
			p := filepath.Join(iocDir, f.name)
			if tryFile(p) {
				*f.dest = p
				resolved++
			}
		}
		if resolved == len(files) {
			return
		}
	}
}
