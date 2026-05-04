// Package config defines the EDR agent's hierarchical configuration and
// provides sane production defaults. It supports multi-source loading
// (YAML files, environment variables, encrypted configs), validation,
// and backward compatibility with legacy configuration formats.
package config

import (
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
		Environment string `yaml:"environment" env:"AGENT_ENV"` // government|enterprise|airgap
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
		Enabled           bool    `yaml:"enabled" env:"LLM_ENABLED"`
		PrimaryProvider   string  `yaml:"primary_provider" env:"LLM_PRIMARY"` // openai|anthropic|grok|groq|gemini|azure|bedrock|ollama|llamacpp
		FallbackProvider  string  `yaml:"fallback_provider" env:"LLM_FALLBACK"`
		LocalProvider     string  `yaml:"local_provider" env:"LLM_LOCAL"` // ollama|llamacpp
		ForceLocal        bool    `yaml:"force_local" env:"LLM_FORCE_LOCAL"`
		LocalThreshold    float32 `yaml:"local_threshold"`
		MinSeverityForLLM string  `yaml:"min_severity_llm"` // medium|high|critical
		MaxConcurrent     int     `yaml:"max_concurrent"`
		TimeoutSec        int     `yaml:"timeout_sec"`

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
			NumGPU    int    `yaml:"num_gpu"` // -1 = all layers on GPU
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
			TopK           int      `yaml:"top_k"`           // number of context chunks to retrieve
			KnowledgeBases []string `yaml:"knowledge_bases"` // mitre_attack|malware_families|threat_reports|cve_db
		} `yaml:"rag"`
	} `yaml:"llm"`

	ML struct {
		Enabled bool `yaml:"enabled" env:"ML_ENABLED"`
		// RequireRuntime aborts startup when ML is enabled if ONNX Runtime cannot
		// initialize or the advanced detection engine (including ML) fails to load.
		RequireRuntime  bool   `yaml:"require_runtime" env:"ML_REQUIRE_RUNTIME"`
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

		VerifyPubKey string `yaml:"verify_pubkey"` // hex-encoded Ed25519 public key for model signatures
	} `yaml:"ml"`

	Detection struct {
		Sigma struct {
			Enabled      bool   `yaml:"enabled"`
			RulesDir     string `yaml:"rules_dir"`
			AutoUpdate   bool   `yaml:"auto_update"`
			UpdateSource string `yaml:"update_source"`
		} `yaml:"sigma"`

		YARA struct {
			Enabled             bool     `yaml:"enabled"`
			RulesDir            string   `yaml:"rules_dir"`
			ScanOnWrite         bool     `yaml:"scan_on_write"`
			ScanOnExec          bool     `yaml:"scan_on_exec"`
			MaxFileSizeMB       int      `yaml:"max_file_size_mb"`
			RescanCooldownSec   int      `yaml:"rescan_cooldown_sec"`
			MaxScansPerMinute   int      `yaml:"max_scans_per_minute"`
			ExcludePathPrefixes []string `yaml:"exclude_path_prefixes"`
		} `yaml:"yara"`

		CustomRules struct {
			Enabled   bool   `yaml:"enabled"`
			RulesPath string `yaml:"rules_path"`
		} `yaml:"custom_rules"`

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

		// PlaybooksPath is the full path to the YAML file (takes precedence over PlaybooksDir).
		PlaybooksPath string `yaml:"playbooks_path"`
		// PlaybooksDir is a directory containing playbooks.yml; used when PlaybooksPath is empty.
		PlaybooksDir string `yaml:"playbooks_dir"`
		// ForensicsDir overrides Forensics.OutputDir for the response layer / collect_forensics.
		ForensicsDir string `yaml:"forensics_dir"`
		// QuarantineDir overrides Quarantine.Dir for template {{quarantine_dir}} when set.
		QuarantineDir string `yaml:"quarantine_dir"`
		Approval      struct {
			Mode        string `yaml:"mode"` // auto|webhook|file
			WebhookURL  string `yaml:"webhook_url"`
			CallbackURL string `yaml:"callback_url"`
			// CallbackListenAddr is the HTTP bind address for /approve and /reject (e.g. ":18765"). Empty disables the callback server.
			CallbackListenAddr string `yaml:"callback_listen_addr"`
			ApprovalDir        string `yaml:"approval_dir"`
			TimeoutSec         int    `yaml:"timeout_sec"`
		} `yaml:"approval"`
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
		MaxCPUPercent   int    `yaml:"max_cpu_percent"`
		MaxMemoryMB     int    `yaml:"max_memory_mb"`
		EventBufferSize int    `yaml:"event_buffer_size"`
		WorkerCount     int    `yaml:"worker_count"`
		BatchSize       int    `yaml:"batch_size"`
		BatchIntervalMs int    `yaml:"batch_interval_ms"`
		Profile         string `yaml:"profile"` // low_resource|balanced|strict
	} `yaml:"performance"`

	Baseline struct {
		Enabled       bool    `yaml:"enabled"`
		StoragePath   string  `yaml:"storage_path"`
		LearningDays  int     `yaml:"learning_days"`
		DeviationMult float64 `yaml:"deviation_mult"`
	} `yaml:"baseline"`

	// Monitoring controls host telemetry collectors (userland vs kernel hooks).
	Monitoring struct {
		Mode             string   `yaml:"mode" env:"EDR_MONITORING_MODE"` // auto|userland|kernel
		KernelEnabled    bool     `yaml:"kernel_enabled" env:"EDR_MONITORING_KERNEL"`
		FIMPaths         []string `yaml:"fim_paths"`
		UserlandFallback bool     `yaml:"userland_fallback"`
		// SecurityProfile standard (default) or regulated — regulated forbids pillar stubs and requires inventory.
		SecurityProfile string `yaml:"security_profile" env:"EDR_MONITORING_SECURITY_PROFILE"`
		// InventoryEnabled collects L1 snapshots; implied true when SecurityProfile is regulated.
		InventoryEnabled bool `yaml:"inventory_enabled" env:"EDR_MONITORING_INVENTORY"`
		// InventoryIntervalSec minimum seconds between heavyweight inventory rescans (0 = every Collect).
		InventoryIntervalSec int `yaml:"inventory_interval_sec"`
		// InventoryPersistSnapshots writes canonical JSON + SHA256 under agent data_dir for manager/delta workflows (G-L1-SYNC-lite).
		InventoryPersistSnapshots bool `yaml:"inventory_persist_snapshots" env:"EDR_MONITORING_INVENTORY_PERSIST"`
		// InventoryStrictListenerAttribution, when true with regulated profile, marks inventory health degraded if listener attribution is count_only or unavailable (tier-1 scans).
		InventoryStrictListenerAttribution bool `yaml:"inventory_strict_listener_attribution"`
		// AdditionalLogTailPaths (optional) tails text files for supplementary logcollector-style coverage (G-L4-BREADTH).
		AdditionalLogTailPaths []string `yaml:"additional_log_tail_paths"`
		// LogTailTelemetryMode: empty or none — health/read-only drain (default); file_events reserved for future capped FileEvent emission (see log_tail collector).
		LogTailTelemetryMode string `yaml:"log_tail_telemetry_mode"`
		// PostureEnabled opts into lightweight read-only posture probes (G-POSTURE); off by default.
		PostureEnabled bool `yaml:"posture_enabled" env:"EDR_MONITORING_POSTURE"`
		// ETWKernelFileObjectCache (Windows) LRU cache FileObject→path for kernel file telemetry.
		ETWKernelFileObjectCache bool `yaml:"etw_kernel_file_object_cache"`
		// ETWRegulatedVerbose (Windows) enables WMI, PS script, pipes, BITS, Task Scheduler ETW together.
		ETWRegulatedVerbose bool `yaml:"etw_regulated_verbose"`

		// ChecklistTier is optional reporting hint: userland|kernel_hooks|full_edr (empty = derive at runtime).
		ChecklistTier string `yaml:"checklist_tier" env:"EDR_MONITORING_CHECKLIST_TIER"`

		// ESFMutePathPrefixes are appended after built-in ESF mutes (macOS only).
		ESFMutePathPrefixes []string `yaml:"esf_mute_path_prefixes"`
		// EnrichExecImageSHA256 hashes process image paths for kernel exec events (all OS; I/O heavy).
		EnrichExecImageSHA256 bool `yaml:"enrich_exec_image_sha256"`
		// ETW optional providers (Windows only; verbose).
		ETWWMIActivity      bool `yaml:"etw_wmi_activity"`
		ETWPowerShellScript bool `yaml:"etw_powershell_script"`
		ETWNamedPipeHandles bool `yaml:"etw_named_pipe_handles"`
		ETWBitsClient       bool `yaml:"etw_bits_client"`
		ETWTaskScheduler    bool `yaml:"etw_task_scheduler"`
		// ETWThreatIntel enables Microsoft-Windows-Threat-Intelligence probing (requires PPL/signing pipeline for production; default off).
		ETWThreatIntel bool `yaml:"etw_threat_intel" env:"EDR_MONITORING_ETW_TI"`
		// HealthSnapshotSec writes monitoring_health.json under data_dir when > 0.
		HealthSnapshotSec int `yaml:"health_snapshot_sec"`
		// RequireKernel, when true, makes monitoring validation fail if the kernel source is absent/unavailable when kernel tier is configured.
		RequireKernel bool `yaml:"require_kernel" env:"EDR_MONITORING_REQUIRE_KERNEL"`

		// --- Optional telemetry (default off for low footprint) ---
		// Linux: journalctl follow for auth-like units (distinct health name journald_auth).
		JournaldAuth bool `yaml:"journald_auth"`
		// Linux: prefer SocketSource for network (PID-attributed vs /proc/net only).
		LinuxPIDNetwork bool `yaml:"linux_pid_network"`
		// LinuxProcNetPIDEnrich: when linux_pid_network is false, map /proc/net socket inodes to PIDs via /proc/*/fd (best-effort; prefer linux_pid_network for full attribution).
		LinuxProcNetPIDEnrich bool `yaml:"linux_proc_net_pid_enrich"`
		// Linux: non-empty opts into fanotify mount marks (needs CAP_SYS_ADMIN).
		LinuxFanotifyMounts []string `yaml:"linux_fanotify_mounts"`
		// Linux: audit NETLINK listener (distinct health name linux_audit).
		LinuxAuditNetlink bool `yaml:"linux_audit_netlink"`
		// Linux: sysfs USB attach/detach watcher.
		LinuxUSBBridge bool `yaml:"linux_usb_hotplug"`

		// Darwin: log stream DNS (health name dns_unified_log).
		DarwinUnifiedLogDNS bool `yaml:"darwin_unified_log_dns"`
		// Darwin: alternate unified-log DNS collector (dns_log_stream_alt health).
		DarwinLogStreamDNSAlt bool `yaml:"darwin_log_stream_dns_alt"`
		// Darwin: use DarwinNetworkSource (tracker-aware lsof snapshot) vs plain NetworkCollector.
		DarwinAttribNetwork bool `yaml:"darwin_attrib_network"`
		// Darwin: auth via unified log stream when /var/log/system.log is unreadable.
		DarwinAuthUnifiedLog bool `yaml:"darwin_auth_unified_log"`
		// Linux: follow journald for ssh/sudo when no /var/log/auth.log|secure.
		LinuxAuthAutoJournal bool `yaml:"linux_auth_auto_journal"`
		// Linux: override path to edr.bpf.o (empty = /var/lib/edr/bpf/edr.bpf.o).
		BPFObjectPath string `yaml:"bpf_object_path"`
		// StreamMaxEPS caps outbound events per second per streaming collector (0 = unlimited).
		StreamMaxEPS int `yaml:"stream_max_eps"`

		// SysmonAutoInstall, when true on Windows, lets the agent install the
		// bundled Sysmon binary + minimal config from `pkg/sysmon/` if Sysmon
		// is not already present. When false (default) the agent only consumes
		// the existing Sysmon Operational channel if installed by the admin.
		SysmonAutoInstall bool `yaml:"sysmon_auto_install" env:"EDR_MONITORING_SYSMON_AUTOINSTALL"`
		// WindowsSysmonNetworkEvents, when false, narrows the Sysmon subscription to exclude
		// network-related EIDs (3 and 12) so elevated kernel ETW network is not double-counted.
		WindowsSysmonNetworkEvents bool `yaml:"windows_sysmon_network_events"`
		// WindowsUserlandNetTable: auto | on | off | force — IP Helper MIB TCP snapshots for userland network pillar.
		// "auto" (default empty): poll when process is not elevated or kernel tier disabled; skip when elevated+kernel to prefer ETW.
		WindowsUserlandNetTable string `yaml:"windows_userland_net_table"`
		// DnsJournalSystemd (Linux): follow systemd-resolved / DNS via journalctl when true.
		DnsJournalSystemd bool `yaml:"dns_journal_systemd"`
		// DnsClientETWWindows: subscribe DNS Client operational channel bookmarked telemetry (Windows).
		DnsClientETWWindows bool `yaml:"dns_client_etw_windows"`
		// DarwinDNSExtraLogPaths append file paths attempted before default /var/log/system.log.
		DarwinDNSExtraLogPaths []string `yaml:"darwin_dns_extra_log_paths"`
	} `yaml:"monitoring"`

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
		Mode      string `yaml:"mode"` // structured|pretty|dual
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
		Enabled           bool     `yaml:"enabled"`
		Mode              string   `yaml:"mode"`
		Endpoint          string   `yaml:"endpoint"`
		TelemetryEndpoint string   `yaml:"telemetry_endpoint"`
		SyslogAddr        string   `yaml:"syslog_addr"`
		KafkaBrokers      []string `yaml:"kafka_brokers"`
		KafkaTopic        string   `yaml:"kafka_topic"`
		RetryMax          int      `yaml:"retry_max"`
		SpoolPath         string   `yaml:"spool_path"`
	} `yaml:"forwarder"`

	RulesFile             string `yaml:"rules_file"`
	RulesVerifyPubKeyPath string `yaml:"rules_verify_pubkey_path"`
	ConfigVerifyPubKey    string `yaml:"config_verify_pubkey"`
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
	cfg.Detection.YARA.MaxFileSizeMB = 8
	cfg.Detection.YARA.RescanCooldownSec = 120
	cfg.Detection.YARA.MaxScansPerMinute = 120
	cfg.Detection.IOC.Enabled = true
	cfg.Detection.Behavioral.BaselineDays = 7
	cfg.Detection.Behavioral.SensitivityLevel = "high"
	cfg.Detection.Behavioral.RansomwareDetect = true
	cfg.Detection.Behavioral.RATDetect = true
	cfg.Detection.Behavioral.ExfilDetect = true
	cfg.Detection.Behavioral.LateralDetect = true

	cfg.Performance.MaxCPUPercent = 5
	cfg.Performance.MaxMemoryMB = 200
	cfg.Performance.EventBufferSize = 2048
	cfg.Performance.WorkerCount = 1
	cfg.Performance.BatchSize = 20
	cfg.Performance.BatchIntervalMs = 15000
	cfg.Performance.Profile = "balanced"
	cfg.Logging.Mode = "structured"

	cfg.Baseline.LearningDays = 7
	cfg.Baseline.DeviationMult = 3.0

	cfg.Monitoring.Mode = "auto"
	cfg.Monitoring.KernelEnabled = true
	cfg.Monitoring.UserlandFallback = true
	cfg.Monitoring.DarwinAuthUnifiedLog = true
	cfg.Monitoring.LinuxAuthAutoJournal = true
	cfg.Monitoring.WindowsSysmonNetworkEvents = true
	cfg.Monitoring.SecurityProfile = "standard"
	cfg.Monitoring.InventoryIntervalSec = 120
	cfg.Monitoring.InventoryPersistSnapshots = true
	cfg.Monitoring.ETWKernelFileObjectCache = true

	cfg.Service.TickInterval = time.Second
	cfg.LegacyResponse.MinKillScore = 90
	cfg.RulesFile = "rules/baseline.yaml"

	return cfg
}
