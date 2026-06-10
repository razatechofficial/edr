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
			NetworkLGBM    string `yaml:"network_lgbm"`
			Ransomware     string `yaml:"ransomware"`
			RATC2          string `yaml:"rat_c2_detector"`
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
			// WindowsPrefetchEnabled copies bounded Prefetch (*.pf) files into artifact manifests.
			WindowsPrefetchEnabled bool `yaml:"windows_prefetch_enabled" env:"EDR_FORENSICS_WIN_PREFETCH"`
			// WindowsAmcacheEnabled snapshots Amcache.hve with shared read (best-effort).
			WindowsAmcacheEnabled bool `yaml:"windows_amcache_enabled" env:"EDR_FORENSICS_WIN_AMCACHE"`
			// SelectedPageMemoryEnabled samples a bounded byte budget from process address spaces (Windows).
			SelectedPageMemoryEnabled bool `yaml:"selected_page_memory_enabled" env:"EDR_FORENSICS_PAGE_MEMORY"`
			// MacosTCCEnabled copies TCC.db from system and user locations when permitted.
			MacosTCCEnabled bool `yaml:"macos_tcc_enabled" env:"EDR_FORENSICS_MACOS_TCC"`
			// FIMDiffEnabled emits capped unified diffs on fsnotify modify for matched globs.
			FIMDiffEnabled bool `yaml:"fim_diff_enabled" env:"EDR_FORENSICS_FIM_DIFF"`
			// FIMDiffMaxFileBytes caps bytes read per file for diff (default 65536).
			FIMDiffMaxFileBytes int `yaml:"fim_diff_max_file_bytes"`
			// FIMDiffPathGlobs selects paths (filepath.Match) for diff-on-modify.
			FIMDiffPathGlobs []string `yaml:"fim_diff_path_globs"`
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

	Compliance struct {
		Enabled              bool   `yaml:"enabled" env:"EDR_COMPLIANCE_ENABLED"`
		RulesDir             string `yaml:"rules_dir" env:"EDR_COMPLIANCE_RULES_DIR"`
		ScanOnStart          bool   `yaml:"scan_on_start"`
		IntervalHours        int    `yaml:"interval_hours"`
		CommandsEnabled      bool   `yaml:"commands_enabled"`
		CommandTimeoutSec    int    `yaml:"command_timeout_sec"`
		EnablePosture        bool   `yaml:"enable_posture"`
		EnableRootcheck      bool   `yaml:"enable_rootcheck"`
		EmitPassedFindings   bool   `yaml:"emit_passed_findings"`
	} `yaml:"compliance"`

	// Monitoring controls host telemetry collectors (userland vs kernel hooks).
	Monitoring struct {
		Mode             string   `yaml:"mode" env:"EDR_MONITORING_MODE"` // auto|userland|kernel
		KernelEnabled    bool     `yaml:"kernel_enabled" env:"EDR_MONITORING_KERNEL"`
		FIMPaths         []string `yaml:"fim_paths"`
		// FIMPreset selects built-in watch lists when fim_paths is empty: standard (default), default, custom.
		FIMPreset string `yaml:"fim_preset" env:"EDR_MONITORING_FIM_PRESET"`
		// FIMIgnorePatterns are glob patterns (basename) skipped by fsnotify FIM, e.g. "*.log".
		FIMIgnorePatterns []string `yaml:"fim_ignore_patterns"`
		UserlandFallback bool     `yaml:"userland_fallback"`
		// SecurityProfile standard (default), regulated, or strict_complete.
		// regulated/strict_complete forbid pillar stubs and require inventory;
		// strict_complete also requires all mandatory pillars to attach.
		SecurityProfile string `yaml:"security_profile" env:"EDR_MONITORING_SECURITY_PROFILE"`
		// InventoryEnabled collects L1 snapshots; implied true when SecurityProfile is regulated.
		InventoryEnabled bool `yaml:"inventory_enabled" env:"EDR_MONITORING_INVENTORY"`
		// InventoryIntervalSec minimum seconds between heavyweight inventory rescans (0 = every Collect).
		InventoryIntervalSec int `yaml:"inventory_interval_sec"`
		// InventoryPersistSnapshots writes canonical JSON + SHA256 under agent data_dir for manager/delta workflows (G-L1-SYNC-lite).
		InventoryPersistSnapshots bool `yaml:"inventory_persist_snapshots" env:"EDR_MONITORING_INVENTORY_PERSIST"`
		// InventoryEmitDeltas writes inventory_delta.json when inventory snapshots change (agent-side artifact; see docs/monitoring_inventory_delta_protocol.md).
		InventoryEmitDeltas bool `yaml:"inventory_emit_deltas"`
		// InventoryStrictListenerAttribution, when true with regulated profile, marks inventory health degraded if listener attribution is count_only or unavailable (tier-1 scans).
		InventoryStrictListenerAttribution bool `yaml:"inventory_strict_listener_attribution"`
		// AdditionalLogTailPaths (optional) tails text files for supplementary logcollector-style coverage (G-L4-BREADTH).
		AdditionalLogTailPaths []string `yaml:"additional_log_tail_paths"`
		// LogTargets is a typed logcollector list (file, eventchannel, journald, command, full_command); see docs/monitoring_rollout_operational_guide.md.
		LogTargets []LogTarget `yaml:"log_targets"`
		// LogTailTelemetryMode: empty or none — health/read-only drain (default); file_events reserved for future capped FileEvent emission (see log_tail collector).
		LogTailTelemetryMode string `yaml:"log_tail_telemetry_mode"`
		// PostureEnabled opts into lightweight read-only posture probes (G-POSTURE); off by default.
		PostureEnabled bool `yaml:"posture_enabled" env:"EDR_MONITORING_POSTURE"`
		// PostureProbes selects optional rootcheck-lite probes (posture_suid_sweep, posture_hidden_pid, posture_hidden_port, posture_dev_walker,
		// ld_so_preload_hash, dev_anomaly, rootkit_iocs).
		PostureProbes []string `yaml:"posture_probes"`
		// ETWKernelFileObjectCache (Windows) LRU cache FileObject→path for kernel file telemetry.
		ETWKernelFileObjectCache bool `yaml:"etw_kernel_file_object_cache"`
		// ETWRegulatedVerbose (Windows) enables WMI, PS script, pipes, BITS, Task Scheduler ETW together.
		ETWRegulatedVerbose bool `yaml:"etw_regulated_verbose"`

		// ChecklistTier is optional reporting hint: userland|kernel_hooks|full_edr (empty = derive at runtime).
		ChecklistTier string `yaml:"checklist_tier" env:"EDR_MONITORING_CHECKLIST_TIER"`

		// ESFMutePathPrefixes are appended after built-in ESF mutes (macOS only).
		ESFMutePathPrefixes []string `yaml:"esf_mute_path_prefixes"`
		// ESFAuthDenyBudgetMs (macOS): fail-closed ESF AUTH when remaining deadline is below this many ms (0=disabled).
		ESFAuthDenyBudgetMs int `yaml:"esf_auth_deny_budget_ms"`
		// PrioritySamplingKernel enables class-biased drops on kernel-tier telemetry after ring-buffer drops exceed threshold.
		PrioritySamplingKernel bool `yaml:"priority_sampling_kernel"`
		// PrioritySamplingThreshold is the ring-buffer drop count before sampling engages (0 = default 100).
		PrioritySamplingThreshold uint64 `yaml:"priority_sampling_threshold"`
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
		// ETWSecurityProviders enables AMSI, Code Integrity, AppLocker, and Windows Defender ETW sessions (optional; may fail without rights).
		ETWSecurityProviders bool `yaml:"etw_security_providers" env:"EDR_MONITORING_ETW_SECURITY"`
		// WindowsMinifilterPort is the FilterConnectCommunicationPort name (e.g. "\\EdrPort"); empty skips minifilter control-plane attach.
		WindowsMinifilterPort string `yaml:"windows_minifilter_port" env:"EDR_MONITORING_WIN_MINIFILTER_PORT"`
		// WindowsWFPCtlProbe opens the local WFP engine handle for monitoring health (elevated agents).
		WindowsWFPCtlProbe bool `yaml:"windows_wfp_ctl_probe"`
		// WindowsWFPMirrorDiagOnly: when true (default), WFP SendMirror only frames for diagnostics (no kernel IO).
		WindowsWFPMirrorDiagOnly bool `yaml:"windows_wfp_mirror_diag_only" env:"EDR_MONITORING_WIN_WFP_MIRROR_DIAG_ONLY"`
		// WindowsControlPlaneRequired makes startup fail when requested WFP/minifilter control planes are unavailable.
		WindowsControlPlaneRequired bool `yaml:"windows_control_plane_required"`
		// WindowsServiceHardening applies SCM failure/recovery actions during service install (see service_hardening_posture.json).
		WindowsServiceHardening bool `yaml:"windows_service_hardening"`
		// WindowsServiceHardeningACL runs best-effort install-directory icacls when WindowsServiceHardening is true.
		WindowsServiceHardeningACL bool `yaml:"windows_service_hardening_acl"`
		// WindowsServiceDaclHardened applies service object DACL hardening (deny stop/delete for non-admin/non-SYSTEM).
		WindowsServiceDaclHardened bool `yaml:"windows_service_dacl_hardened"`
		// WindowsServiceLaunchProtected sets SERVICE_LAUNCH_PROTECTED (Windows Light) during install when hardening is enabled (legacy; prefer windows_service_launch_protected_tier).
		WindowsServiceLaunchProtected bool `yaml:"windows_service_launch_protected"`
		// WindowsServiceLaunchProtectedTier selects SCM launch protection: none | windows_light | antimalware_light (AM-PPL).
		WindowsServiceLaunchProtectedTier string `yaml:"windows_service_launch_protected_tier" env:"EDR_MONITORING_WIN_LAUNCH_PROTECTED_TIER"`
		// WindowsPPLRequired fails agent startup when the process is not running as AM-PPL with Antimalware Authenticode EKU.
		WindowsPPLRequired bool `yaml:"windows_ppl_required" env:"EDR_MONITORING_WIN_PPL_REQUIRED"`
		// WindowsWDMProtectEnabled registers the agent PID with edr_protect.sys (ObRegisterCallbacks) when the signed driver is installed.
		WindowsWDMProtectEnabled bool `yaml:"windows_wdm_protect_enabled" env:"EDR_MONITORING_WIN_WDM_PROTECT"`
		// WindowsWDMProtectDevice user-mode device path for edr_protect.sys (default \\.\EdrProtect).
		WindowsWDMProtectDevice string `yaml:"windows_wdm_protect_device" env:"EDR_MONITORING_WIN_WDM_DEVICE"`
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
		// LinuxAuditManagedRules installs a tiny auditctl watch under /var/lib/edr for FIM correlation probes (feature-gated; requires auditctl + CAP_AUDIT_CONTROL).
		LinuxAuditManagedRules bool `yaml:"linux_audit_managed_rules"`
		// LinuxBPFPinPath pins eBPF maps under this bpffs path (empty = no pinning). Recommended: /sys/fs/bpf/edr_<agent> namespaced dir.
		LinuxBPFPinPath string `yaml:"linux_bpf_pin_path" env:"EDR_MONITORING_BPF_PIN_PATH"`
		// SchedHooksEnabled attaches sched tracepoints and emits scheduler telemetry (Linux eBPF; very high volume).
		SchedHooksEnabled bool `yaml:"sched_hooks_enabled" env:"EDR_MONITORING_SCHED_HOOKS"`
		// LinuxFileEventDedupeMs drops duplicate file telemetry paths across fanotify vs audit within this window (0 = disabled).
		LinuxFileEventDedupeMs int `yaml:"linux_file_event_dedupe_ms"`
		// Linux: sysfs USB attach/detach watcher.
		LinuxUSBBridge bool `yaml:"linux_usb_hotplug"`
		// LinuxRootcheckEnabled runs periodic rootcheck-style probes (hidden pid/port, suid drift).
		LinuxRootcheckEnabled bool `yaml:"linux_rootcheck_enabled" env:"EDR_MONITORING_LINUX_ROOTCHECK"`
		// LinuxRootcheckIntervalSec controls rootcheck cadence (seconds, default 300).
		LinuxRootcheckIntervalSec int `yaml:"linux_rootcheck_interval_sec"`
		// LinuxRootcheckSUIDPrefixes controls prefixes scanned for suid/sgid drift.
		LinuxRootcheckSUIDPrefixes []string `yaml:"linux_rootcheck_suid_prefixes"`
		// LinuxRootcheckPortScan attempts bind-vs-/proc-net hidden-port probes (intrusive).
		LinuxRootcheckPortScan bool `yaml:"linux_rootcheck_port_scan" env:"EDR_MONITORING_LINUX_ROOTCHECK_PORTS"`
		// LinuxRootcheckPortList TCP/UDP ports to probe when LinuxRootcheckPortScan is true.
		LinuxRootcheckPortList []int `yaml:"linux_rootcheck_port_list"`
		// LinuxHiddenModule compares /proc/modules vs /sys/module (intrusive heuristic).
		LinuxHiddenModule bool `yaml:"linux_hidden_module"`
		// LinuxInetDiagHiddenSocket cross-checks netlink SOCK_DIAG vs /proc/net (requires CAP_NET_ADMIN best-effort).
		LinuxInetDiagHiddenSocket bool `yaml:"linux_inet_diag_hidden_socket"`
		// LinuxLSMFimEnabled emits observe-only LSM FIM events (requires CONFIG_BPF_LSM; high volume).
		LinuxLSMFimEnabled bool `yaml:"linux_lsm_fim_enabled" env:"EDR_MONITORING_LINUX_LSM_FIM"`

		// DarwinNEBundleID filters systemextensionsctl health parsing for this extension id (optional).
		DarwinNEBundleID string `yaml:"darwin_ne_bundle_id"`
		// Darwin: log stream DNS (health name dns_unified_log).
		DarwinUnifiedLogDNS bool `yaml:"darwin_unified_log_dns"`
		// Darwin: alternate unified-log DNS collector (dns_log_stream_alt health).
		DarwinLogStreamDNSAlt bool `yaml:"darwin_log_stream_dns_alt"`
		// Darwin: use DarwinNetworkSource (tracker-aware lsof snapshot) vs plain NetworkCollector.
		DarwinAttribNetwork bool `yaml:"darwin_attrib_network"`
		// Darwin: auth via unified log stream when /var/log/system.log is unreadable.
		DarwinAuthUnifiedLog bool `yaml:"darwin_auth_unified_log"`
		// Darwin: unified-log security subsystems for imported macOS Sigma UL rules.
		DarwinUnifiedLogSecurity bool `yaml:"darwin_unified_log_security"`
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

		// TLSFingerprintLocal computes JA3/JA4 when raw ClientHello bytes are present in kernel JSON.
		TLSFingerprintLocal bool `yaml:"tls_fingerprint_local" env:"EDR_MONITORING_TLS_FP_LOCAL"`
		// CommunityIDLocal fills community-id v1 when a 5-tuple is complete (default true via Defaults()).
		CommunityIDLocal bool `yaml:"community_id_local" env:"EDR_MONITORING_COMMUNITY_ID_LOCAL"`

		// WindowsAmsiTamperEnabled checks AMSI exports for unexpected prologues (best-effort).
		WindowsAmsiTamperEnabled bool `yaml:"windows_amsi_tamper_enabled"`
		// WindowsEtwTamperEnabled checks ntdll ETW export prologues (best-effort).
		WindowsEtwTamperEnabled bool `yaml:"windows_etw_tamper_enabled"`
		// WindowsTamperIntervalSec recheck cadence for AMSI/ETW tamper probes (default 60).
		WindowsTamperIntervalSec int `yaml:"windows_tamper_interval_sec"`
		// WindowsPPIDSpoofDetector compares ETW parent PID vs NtQueryInformationProcess inherited PID on process-create JSON.
		WindowsPPIDSpoofDetector bool `yaml:"windows_ppid_spoof_detector"`
		// WindowsADSEnumerator walks prefixes for non-default NTFS streams.
		WindowsADSEnumerator bool `yaml:"windows_ads_enumerator"`
		// WindowsADSPathGlobs optional path filters (filepath.Match) under search roots.
		WindowsADSPathGlobs []string `yaml:"windows_ads_path_globs"`
		// WindowsSACLWhodata maps Security 4663 events from log_targets into FileEvent rows.
		WindowsSACLWhodata bool `yaml:"windows_sacl_whodata"`
		// WindowsAutorunsLite enumerates common Run/IFEO/AppInit/LSA/Winlogon/task persistence keys.
		WindowsAutorunsLite bool `yaml:"windows_autoruns_lite"`
		// WindowsAutorunsIntervalSec cadence for autoruns-lite (default 300).
		WindowsAutorunsIntervalSec int `yaml:"windows_autoruns_interval_sec"`
		// WindowsCOMHijackHunt scans HKCU/HKLM CLSID hijack divergence (heavy).
		WindowsCOMHijackHunt bool `yaml:"windows_com_hijack_hunt"`
		// WindowsCOMHijackIntervalSec cadence for COM hijack hunt (seconds; default 600).
		WindowsCOMHijackIntervalSec int `yaml:"windows_com_hijack_interval_sec"`
		// WindowsDLLSearchPosture emits events when DLL search hardening knobs are weakened.
		WindowsDLLSearchPosture bool `yaml:"windows_dll_search_posture"`
		// WindowsWMIPersistenceHunt dumps WMI subscription classes (elevated WMI).
		WindowsWMIPersistenceHunt bool `yaml:"windows_wmi_persistence_hunt"`
		// WindowsWMIIntervalSec cadence for WMI persistence hunt (seconds; default 3600).
		WindowsWMIIntervalSec int `yaml:"windows_wmi_interval_sec"`

		// MacosTCCWatch watches TCC.db for row-level changes (best-effort; SIP may block).
		MacosTCCWatch bool `yaml:"macos_tcc_watch"`
		// MacosTCCMaxRows caps sqlite row reads per poll (0 = unbounded).
		MacosTCCMaxRows int `yaml:"macos_tcc_max_rows"`
		// MacosAutostartEnumerator scans LaunchAgents/Daemons, login items, cron paths.
		MacosAutostartEnumerator bool `yaml:"macos_autostart_enumerator"`
		// MacosCodesignSweep verifies codesign for running process images periodically.
		MacosCodesignSweep bool `yaml:"macos_codesign_sweep"`
		// MacosCodesignIntervalSec cadence for codesign sweep (default 600).
		MacosCodesignIntervalSec int `yaml:"macos_codesign_interval_sec"`
		// MacosCodesignMaxProcs caps binaries verified per sweep (0 = unlimited; dedupe by path applies).
		MacosCodesignMaxProcs int `yaml:"macos_codesign_max_procs"`
		// MacosNotarizationPosture polls XProtect/MRT/Gatekeeper/SIP posture (cheap).
		MacosNotarizationPosture bool `yaml:"macos_notarization_posture"`
		// MacosNotarizationIntervalSec posture poll cadence for notarization checks (seconds; default 3600).
		MacosNotarizationIntervalSec int `yaml:"macos_notarization_interval_sec"`

		// TLSFingerprintServerLocal computes JA3S/JA4S when ServerHello payload is present in JSON.
		TLSFingerprintServerLocal bool `yaml:"tls_fingerprint_server_local"`
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
		// SealEnvelopes wraps alert JSON in AES-GCM (see internal/transport/sealed_envelope.go).
		SealEnvelopes bool   `yaml:"seal_envelopes"`
		SealKeyPath   string `yaml:"seal_key_path"`
		SealKeyID     string `yaml:"seal_key_id"`
	} `yaml:"forwarder"`

	RulesFile             string `yaml:"rules_file"`
	RulesVerifyPubKeyPath string `yaml:"rules_verify_pubkey_path"`
	PolicyVerifyPubKeyPath string `yaml:"policy_verify_pubkey_path"`
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
	cfg.Detection.CustomRules.Enabled = true
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

	cfg.Compliance.Enabled = true
	cfg.Compliance.RulesDir = "rules/compliance/sca"
	cfg.Compliance.ScanOnStart = true
	cfg.Compliance.IntervalHours = 12
	cfg.Compliance.CommandsEnabled = true
	cfg.Compliance.CommandTimeoutSec = 30
	cfg.Compliance.EnablePosture = true
	cfg.Compliance.EnableRootcheck = true
	cfg.Compliance.EmitPassedFindings = false

	cfg.Monitoring.Mode = "auto"
	cfg.Monitoring.FIMPreset = "standard"
	cfg.Monitoring.KernelEnabled = true
	cfg.Monitoring.UserlandFallback = true
	cfg.Monitoring.DarwinAuthUnifiedLog = true
	cfg.Monitoring.DarwinUnifiedLogSecurity = true
	cfg.Monitoring.LinuxAuthAutoJournal = true
	cfg.Monitoring.WindowsSysmonNetworkEvents = true
	cfg.Monitoring.SecurityProfile = "standard"
	cfg.Monitoring.InventoryIntervalSec = 120
	cfg.Monitoring.InventoryPersistSnapshots = true
	cfg.Monitoring.ETWKernelFileObjectCache = true
	cfg.Monitoring.ETWSecurityProviders = true
	cfg.Monitoring.WindowsWFPCtlProbe = true
	cfg.Monitoring.WindowsWFPMirrorDiagOnly = true
	cfg.Monitoring.WindowsControlPlaneRequired = false
	cfg.Monitoring.WindowsServiceHardening = false
	cfg.Monitoring.WindowsServiceHardeningACL = false
	cfg.Monitoring.WindowsServiceDaclHardened = false
	cfg.Monitoring.WindowsServiceLaunchProtected = false
	cfg.Monitoring.WindowsServiceLaunchProtectedTier = ""
	cfg.Monitoring.WindowsPPLRequired = false
	cfg.Monitoring.WindowsWDMProtectEnabled = true
	cfg.Monitoring.WindowsWDMProtectDevice = `\\.\EdrProtect`
	cfg.Monitoring.LinuxRootcheckEnabled = false
	cfg.Monitoring.LinuxRootcheckIntervalSec = 300
	cfg.Monitoring.LinuxRootcheckSUIDPrefixes = []string{"/usr", "/bin", "/sbin", "/opt"}
	cfg.Monitoring.LinuxRootcheckPortScan = false
	cfg.Monitoring.LinuxRootcheckPortList = []int{22, 80, 443, 53, 3306, 5432, 6379, 8080, 8443}
	cfg.Monitoring.LinuxHiddenModule = false
	cfg.Monitoring.LinuxInetDiagHiddenSocket = false
	cfg.Monitoring.CommunityIDLocal = true
	cfg.Monitoring.TLSFingerprintServerLocal = true
	cfg.Monitoring.WindowsTamperIntervalSec = 60
	cfg.Monitoring.WindowsAutorunsIntervalSec = 300
	cfg.Monitoring.WindowsCOMHijackIntervalSec = 600
	cfg.Monitoring.WindowsDLLSearchPosture = true
	cfg.Monitoring.WindowsWMIIntervalSec = 3600
	cfg.Monitoring.MacosCodesignIntervalSec = 600
	cfg.Monitoring.MacosTCCMaxRows = 0
	cfg.Monitoring.MacosCodesignMaxProcs = 0
	cfg.Monitoring.MacosNotarizationPosture = true
	cfg.Monitoring.MacosNotarizationIntervalSec = 3600

	cfg.Service.TickInterval = time.Second
	cfg.LegacyResponse.MinKillScore = 90
	cfg.RulesFile = "rules/baseline.yaml"

	return cfg
}
