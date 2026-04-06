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
