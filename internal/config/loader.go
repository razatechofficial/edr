package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

	if err := Validate(&cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
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

// applyResourcePathDefaults resolves empty detection, ML, and rules paths when
// the config file lives next to a standard repo layout (configs/agent.yaml →
// ../rules, ../models) or when Debian-style shipped paths exist under
// /usr/share/edr.
func applyResourcePathDefaults(cfg *Config, configPath string) {
	if configPath == "" {
		return
	}
	base := filepath.Dir(configPath)
	repoRules := filepath.Clean(filepath.Join(base, "..", "rules"))
	repoModels := filepath.Clean(filepath.Join(base, "..", "models"))

	tryDir := func(path string) bool {
		fi, err := os.Stat(path)
		return err == nil && fi.IsDir()
	}
	tryFile := func(path string) bool {
		fi, err := os.Stat(path)
		return err == nil && !fi.IsDir()
	}

	if cfg.Detection.Sigma.Enabled && cfg.Detection.Sigma.RulesDir == "" {
		for _, p := range []string{
			filepath.Join(repoRules, "sigma"),
			"/usr/share/edr/rules/sigma",
		} {
			if tryDir(p) {
				cfg.Detection.Sigma.RulesDir = p
				break
			}
		}
	}
	if cfg.Detection.YARA.Enabled && cfg.Detection.YARA.RulesDir == "" {
		for _, p := range []string{
			filepath.Join(repoRules, "yara"),
			"/usr/share/edr/rules/yara",
		} {
			if tryDir(p) {
				cfg.Detection.YARA.RulesDir = p
				break
			}
		}
	}
	if cfg.Detection.CustomRules.Enabled && cfg.Detection.CustomRules.RulesPath == "" {
		for _, p := range []string{
			filepath.Join(repoRules, "custom"),
			"/usr/share/edr/rules/custom",
		} {
			if tryDir(p) || tryFile(p) {
				cfg.Detection.CustomRules.RulesPath = p
				break
			}
		}
		if cfg.Detection.CustomRules.RulesPath == "" {
			sample := filepath.Join(repoRules, "custom", "sample_rules.yaml")
			if tryFile(sample) {
				cfg.Detection.CustomRules.RulesPath = sample
			}
		}
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
		// Keep a working relative path when the process CWD already resolves it
		// (typical local dev from repo root).
		if _, err := os.Stat(cfg.RulesFile); err != nil {
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
