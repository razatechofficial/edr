// Package config defines the EDR agent's hierarchical configuration and
// provides sane production defaults. It supports multi-source loading
// (YAML files, environment variables, encrypted configs), validation,
// and backward compatibility with legacy configuration formats.
package config

import (
	"runtime"
	"time"
)

// Config is the top-level configuration for the EDR agent. It covers agent
// identity, server connectivity, LLM/ML inference, detection engines,
// automated response, threat intelligence, self-protection, and performance
// tuning. Legacy fields are retained for backward compatibility with older
// agent.example.yaml files.
type Config struct {
	Agent struct {
		ID          string `yaml:"id" env:"AGENT_ID"`
		Name        string `yaml:"name" env:"AGENT_NAME"`
		Version     string `yaml:"version"`
		Environment string `yaml:"environment" env:"AGENT_ENV"`  // government|enterprise|airgap
		LogLevel    string `yaml:"log_level" env:"LOG_LEVEL"`
		DataDir     string `yaml:"data_dir" env:"DATA_DIR"`
		TempDir     string `yaml:"temp_dir"`
	} `yaml:"agent"`

	Server struct {
		Endpoint     string `yaml:"endpoint" env:"SERVER_ENDPOINT"`
		GRPCPort     int    `yaml:"grpc_port" env:"SERVER_GRPC_PORT"`
		TLSCertPath  string `yaml:"tls_cert" env:"TLS_CERT_PATH"`
		TLSKeyPath   string `yaml:"tls_key" env:"TLS_KEY_PATH"`
		CACertPath   string `yaml:"ca_cert" env:"CA_CERT_PATH"`
		MutualTLS    bool   `yaml:"mutual_tls" env:"MUTUAL_TLS"`
		HeartbeatSec int    `yaml:"heartbeat_sec"`
		ReconnectSec int    `yaml:"reconnect_sec"`
		AirGapMode   bool   `yaml:"airgap_mode" env:"AIRGAP_MODE"`
	} `yaml:"server"`

	LLM struct {
		Enabled          bool    `yaml:"enabled" env:"LLM_ENABLED"`
		PrimaryProvider  string  `yaml:"primary_provider" env:"LLM_PRIMARY"`   // openai|anthropic|grok|groq|gemini|azure|bedrock|ollama|llamacpp
		FallbackProvider string  `yaml:"fallback_provider" env:"LLM_FALLBACK"`
		LocalProvider    string  `yaml:"local_provider" env:"LLM_LOCAL"`       // ollama|llamacpp
		ForceLocal       bool    `yaml:"force_local" env:"LLM_FORCE_LOCAL"`
		LocalThreshold   float32 `yaml:"local_threshold"`
		MinSeverityForLLM string `yaml:"min_severity_llm"` // medium|high|critical
		MaxConcurrent    int     `yaml:"max_concurrent"`
		TimeoutSec       int     `yaml:"timeout_sec"`

		OpenAI struct {
			APIKey      string  `yaml:"api_key" env:"OPENAI_API_KEY"`
			Model       string  `yaml:"model" env:"OPENAI_MODEL"`
			BaseURL     string  `yaml:"base_url" env:"OPENAI_BASE_URL"`
			OrgID       string  `yaml:"org_id" env:"OPENAI_ORG_ID"`
			MaxTokens   int     `yaml:"max_tokens"`
			Temperature float32 `yaml:"temperature"`
		} `yaml:"openai"`

		Anthropic struct {
			APIKey    string `yaml:"api_key" env:"ANTHROPIC_API_KEY"`
			Model     string `yaml:"model" env:"ANTHROPIC_MODEL"`
			MaxTokens int    `yaml:"max_tokens"`
		} `yaml:"anthropic"`

		Grok struct {
			APIKey    string `yaml:"api_key" env:"GROK_API_KEY"`
			Model     string `yaml:"model" env:"GROK_MODEL"`
			BaseURL   string `yaml:"base_url"`
			MaxTokens int    `yaml:"max_tokens"`
		} `yaml:"grok"`

		Groq struct {
			APIKey    string `yaml:"api_key" env:"GROQ_API_KEY"`
			Model     string `yaml:"model" env:"GROQ_MODEL"`
			BaseURL   string `yaml:"base_url"`
			MaxTokens int    `yaml:"max_tokens"`
		} `yaml:"groq"`

		Gemini struct {
			APIKey    string `yaml:"api_key" env:"GEMINI_API_KEY"`
			Model     string `yaml:"model" env:"GEMINI_MODEL"`
			ProjectID string `yaml:"project_id" env:"GEMINI_PROJECT_ID"`
			Location  string `yaml:"location"`
		} `yaml:"gemini"`

		Azure struct {
			TenantID       string `yaml:"tenant_id" env:"AZURE_TENANT_ID"`
			ClientID       string `yaml:"client_id" env:"AZURE_CLIENT_ID"`
			ClientSecret   string `yaml:"client_secret" env:"AZURE_CLIENT_SECRET"`
			Endpoint       string `yaml:"endpoint" env:"AZURE_OPENAI_ENDPOINT"`
			DeploymentName string `yaml:"deployment_name" env:"AZURE_DEPLOYMENT_NAME"`
			APIVersion     string `yaml:"api_version"`
		} `yaml:"azure"`

		Bedrock struct {
			Region          string `yaml:"region" env:"AWS_REGION"`
			AccessKeyID     string `yaml:"access_key_id" env:"AWS_ACCESS_KEY_ID"`
			SecretAccessKey string `yaml:"secret_access_key" env:"AWS_SECRET_ACCESS_KEY"`
			ModelID         string `yaml:"model_id" env:"BEDROCK_MODEL_ID"`
		} `yaml:"bedrock"`

		Ollama struct {
			Endpoint  string `yaml:"endpoint" env:"OLLAMA_ENDPOINT"` // default: http://localhost:11434
			Model     string `yaml:"model" env:"OLLAMA_MODEL"`       // phi3|mistral|llama3|gemma3
			KeepAlive string `yaml:"keep_alive"`
			NumCtx    int    `yaml:"num_ctx"`
			NumGPU    int    `yaml:"num_gpu"`    // -1 = all layers on GPU
			NumThread int    `yaml:"num_thread"`
		} `yaml:"ollama"`

		LlamaCpp struct {
			ServerEndpoint string `yaml:"endpoint" env:"LLAMACPP_ENDPOINT"`
			ModelPath      string `yaml:"model_path" env:"LLAMACPP_MODEL"`
			ContextSize    int    `yaml:"context_size"`
			GPULayers      int    `yaml:"gpu_layers"`
			Threads        int    `yaml:"threads"`
		} `yaml:"llamacpp"`

		RAG struct {
			Enabled        bool     `yaml:"enabled"`
			VectorDBPath   string   `yaml:"vectordb_path"`
			EmbeddingModel string   `yaml:"embedding_model"`
			ChunkSize      int      `yaml:"chunk_size"`
			TopK           int      `yaml:"top_k"` // number of context chunks to retrieve
			KnowledgeBases []string `yaml:"knowledge_bases"` // mitre_attack|malware_families|threat_reports|cve_db
		} `yaml:"rag"`
	} `yaml:"llm"`

	ML struct {
		Enabled         bool   `yaml:"enabled" env:"ML_ENABLED"`
		ModelsDir       string `yaml:"models_dir" env:"ML_MODELS_DIR"`
		AutoUpdate      bool   `yaml:"auto_update"`
		UpdateIntervalH int    `yaml:"update_interval_hours"`

		Models struct {
			PEClassifier   string `yaml:"pe_classifier"`
			BehaviorLSTM   string `yaml:"behavior_lstm"`
			NetworkAnomaly string `yaml:"network_anomaly"`
			Ransomware     string `yaml:"ransomware"`
		} `yaml:"models"`

		Thresholds struct {
			PEMalicious     float32 `yaml:"pe_malicious"`     // default 0.80
			BehaviorAnomaly float32 `yaml:"behavior_anomaly"` // default 0.75
			RansomwareScore float32 `yaml:"ransomware_score"` // default 0.85
			NetworkAnomaly  float32 `yaml:"network_anomaly"`  // default 0.70
		} `yaml:"thresholds"`

		ONNX struct {
			NumThreads  int  `yaml:"num_threads"`
			UseGPU      bool `yaml:"use_gpu"`
			GPUDeviceID int  `yaml:"gpu_device_id"`
		} `yaml:"onnx"`
	} `yaml:"ml"`

	Detection struct {
		Sigma struct {
			Enabled      bool   `yaml:"enabled"`
			RulesDir     string `yaml:"rules_dir"`
			AutoUpdate   bool   `yaml:"auto_update"`
			UpdateSource string `yaml:"update_source"`
		} `yaml:"sigma"`

		YARA struct {
			Enabled       bool   `yaml:"enabled"`
			RulesDir      string `yaml:"rules_dir"`
			ScanOnWrite   bool   `yaml:"scan_on_write"`
			ScanOnExec    bool   `yaml:"scan_on_exec"`
			MaxFileSizeMB int    `yaml:"max_file_size_mb"`
		} `yaml:"yara"`

		IOC struct {
			Enabled         bool   `yaml:"enabled"`
			HashDBPath      string `yaml:"hash_db_path"`
			IPDBPath        string `yaml:"ip_db_path"`
			DomainDBPath    string `yaml:"domain_db_path"`
			UpdateIntervalH int    `yaml:"update_interval_hours"`
		} `yaml:"ioc"`

		Behavioral struct {
			BaselineDays     int    `yaml:"baseline_days"`
			SensitivityLevel string `yaml:"sensitivity"` // low|medium|high|paranoid
			RansomwareDetect bool   `yaml:"ransomware_detect"`
			RATDetect        bool   `yaml:"rat_detect"`
			ExfilDetect      bool   `yaml:"exfil_detect"`
			LateralDetect    bool   `yaml:"lateral_movement_detect"`
		} `yaml:"behavioral"`
	} `yaml:"detection"`

	Response struct {
		AutoResponse bool `yaml:"auto_response" env:"AUTO_RESPONSE"`

		Actions struct {
			KillProcess     bool `yaml:"kill_process"`
			QuarantineFile  bool `yaml:"quarantine_file"`
			NetworkIsolate  bool `yaml:"network_isolate"`
			BlockHash       bool `yaml:"block_hash"`
			DisableUser     bool `yaml:"disable_user"`
			CollectForensic bool `yaml:"collect_forensics"`
			TakeSnapshot    bool `yaml:"take_snapshot"`
		} `yaml:"actions"`

		AutoResponseRules struct {
			KillOnCritical  bool `yaml:"kill_on_critical"`
			IsolateOnRansom bool `yaml:"isolate_on_ransomware"`
			IsolateOnAPT    bool `yaml:"isolate_on_apt"`
		} `yaml:"auto_response_rules"`

		Quarantine struct {
			Dir          string `yaml:"dir"`
			EncryptFiles bool   `yaml:"encrypt_files"`
			MaxSizeMB    int    `yaml:"max_size_mb"`
		} `yaml:"quarantine"`

		Forensics struct {
			AutoCollect    bool   `yaml:"auto_collect"`
			IncludeMemory  bool   `yaml:"include_memory_dump"`
			OutputDir      string `yaml:"output_dir"`
			ChainOfCustody bool   `yaml:"chain_of_custody"`
		} `yaml:"forensics"`
	} `yaml:"response"`

	ThreatIntel struct {
		MISP struct {
			Enabled         bool   `yaml:"enabled"`
			URL             string `yaml:"url" env:"MISP_URL"`
			APIKey          string `yaml:"api_key" env:"MISP_API_KEY"`
			VerifySSL       bool   `yaml:"verify_ssl"`
			UpdateIntervalH int    `yaml:"update_interval_hours"`
		} `yaml:"misp"`

		OTX struct {
			Enabled         bool   `yaml:"enabled"`
			APIKey          string `yaml:"api_key" env:"OTX_API_KEY"`
			UpdateIntervalH int    `yaml:"update_interval_hours"`
		} `yaml:"otx"`

		CustomFeeds []CustomFeed `yaml:"custom_feeds"`
	} `yaml:"threat_intel"`

	SelfProtect struct {
		Enabled          bool `yaml:"enabled"`
		Watchdog         bool `yaml:"watchdog"`
		AntiDebug        bool `yaml:"anti_debug"`
		IntegrityCheck   bool `yaml:"integrity_check"`
		ProtectedProcess bool `yaml:"protected_process"`
	} `yaml:"self_protect"`

	Performance struct {
		MaxCPUPercent   int `yaml:"max_cpu_percent"`
		MaxMemoryMB     int `yaml:"max_memory_mb"`
		EventBufferSize int `yaml:"event_buffer_size"`
		WorkerCount     int `yaml:"worker_count"`
		BatchSize       int `yaml:"batch_size"`
		BatchIntervalMs int `yaml:"batch_interval_ms"`
	} `yaml:"performance"`

	// Legacy fields for backward compatibility with existing agent.example.yaml.
	// These map to the older flat configuration layout. Use migrateLegacy in the
	// loader to populate these from old-style YAML keys.
	Service struct {
		EndpointID   string        `yaml:"endpoint_id"`
		TickInterval time.Duration `yaml:"tick_interval"`
		PIDFile      string        `yaml:"pid_file"`
	} `yaml:"service"`

	Logging struct {
		Level     string `yaml:"level"`
		AlertFile string `yaml:"alert_file"`
		AuditFile string `yaml:"audit_file"`
	} `yaml:"logging"`

	LegacyResponse struct {
		AllowKill          bool     `yaml:"allow_kill"`
		AutoKillEnabled    bool     `yaml:"auto_kill_enabled"`
		MinKillScore       int      `yaml:"min_kill_score"`
		KillRuleAllowlist  []string `yaml:"kill_rule_allowlist"`
		ProtectedProcesses []string `yaml:"protected_processes"`
	} `yaml:"response_legacy"`

	Forwarder struct {
		Enabled      bool     `yaml:"enabled"`
		Mode         string   `yaml:"mode"`
		Endpoint     string   `yaml:"endpoint"`
		SyslogAddr   string   `yaml:"syslog_addr"`
		KafkaBrokers []string `yaml:"kafka_brokers"`
		KafkaTopic   string   `yaml:"kafka_topic"`
		RetryMax     int      `yaml:"retry_max"`
		SpoolPath    string   `yaml:"spool_path"`
	} `yaml:"forwarder"`

	RulesFile             string `yaml:"rules_file"`
	RulesVerifyPubKeyPath string `yaml:"rules_verify_pubkey_path"`
}

// CustomFeed represents an external threat intelligence feed.
type CustomFeed struct {
	Name            string `yaml:"name"`
	URL             string `yaml:"url"`
	Format          string `yaml:"format"` // stix|taxii|csv|json
	APIKey          string `yaml:"api_key"`
	UpdateIntervalH int    `yaml:"update_interval_hours"`
}

// Defaults returns a Config populated with sane production defaults.
func Defaults() Config {
	var cfg Config

	cfg.Agent.LogLevel = "info"
	cfg.Agent.DataDir = "/var/lib/edr"
	cfg.Agent.TempDir = "/tmp/edr"

	cfg.Server.GRPCPort = 50051
	cfg.Server.HeartbeatSec = 30
	cfg.Server.ReconnectSec = 5
	cfg.Server.MutualTLS = true

	cfg.LLM.PrimaryProvider = "grok"
	cfg.LLM.LocalProvider = "ollama"
	cfg.LLM.MinSeverityForLLM = "medium"
	cfg.LLM.MaxConcurrent = 4
	cfg.LLM.TimeoutSec = 30
	cfg.LLM.Grok.BaseURL = "https://api.x.ai/v1"
	cfg.LLM.Ollama.Endpoint = "http://localhost:11434"

	cfg.ML.Thresholds.PEMalicious = 0.80
	cfg.ML.Thresholds.BehaviorAnomaly = 0.75
	cfg.ML.Thresholds.RansomwareScore = 0.85
	cfg.ML.Thresholds.NetworkAnomaly = 0.70

	cfg.Detection.Sigma.Enabled = true
	cfg.Detection.YARA.Enabled = true
	cfg.Detection.IOC.Enabled = true
	cfg.Detection.Behavioral.BaselineDays = 7
	cfg.Detection.Behavioral.SensitivityLevel = "high"
	cfg.Detection.Behavioral.RansomwareDetect = true
	cfg.Detection.Behavioral.RATDetect = true
	cfg.Detection.Behavioral.ExfilDetect = true
	cfg.Detection.Behavioral.LateralDetect = true

	cfg.Performance.MaxCPUPercent = 5
	cfg.Performance.MaxMemoryMB = 200
	cfg.Performance.EventBufferSize = 65536
	cfg.Performance.WorkerCount = runtime.NumCPU()
	cfg.Performance.BatchSize = 50
	cfg.Performance.BatchIntervalMs = 15000

	cfg.Service.TickInterval = time.Second
	cfg.LegacyResponse.MinKillScore = 90
	cfg.RulesFile = "rules/baseline.yaml"

	return cfg
}
