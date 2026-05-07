package forensics

// ForensicsDeepConfig gates optional deep artifact collectors (best-effort).
type ForensicsDeepConfig struct {
	WindowsPrefetchEnabled     bool
	WindowsAmcacheEnabled      bool
	SelectedPageMemoryEnabled  bool
	MacosTCCEnabled            bool
	// WorkDir is the base directory for copied files (e.g. DFIR work dir or temp).
	WorkDir string
	// Byte budget for selected-page memory sampling (default applied in platform code).
	SelectedPageMemoryMaxBytes int
	// MaxPrefetchFiles caps Windows Prefetch copies (default 256).
	MaxPrefetchFiles int
}

// AnyEnabled reports whether any deep collector flag is set.
func (c ForensicsDeepConfig) AnyEnabled() bool {
	return c.WindowsPrefetchEnabled || c.WindowsAmcacheEnabled || c.SelectedPageMemoryEnabled || c.MacosTCCEnabled
}

// DeepArtifactsBundle is embedded in SystemArtifacts when deep collection runs.
type DeepArtifactsBundle struct {
	Prefetch           []CopiedFileEntry `json:"prefetch,omitempty"`
	PrefetchError      string            `json:"prefetch_error,omitempty"`
	Amcache            *CopiedFileEntry  `json:"amcache,omitempty"`
	AmcacheError       string            `json:"amcache_error,omitempty"`
	SelectedPageMemory []PageMemoryChunk `json:"selected_page_memory,omitempty"`
	PageMemoryError    string            `json:"page_memory_error,omitempty"`
	TCC                []CopiedFileEntry `json:"tcc,omitempty"`
	TCCError           string            `json:"tcc_error,omitempty"`
	TCCDegraded        string            `json:"tcc_degraded,omitempty"`
}

// CopiedFileEntry describes one copied file with chain-of-custody hash.
type CopiedFileEntry struct {
	Source  string `json:"source"`
	Dest    string `json:"dest,omitempty"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Copied  bool   `json:"copied"`
	Note    string `json:"note,omitempty"`
}

// PageMemoryChunk is a bounded ReadProcessMemory sample.
type PageMemoryChunk struct {
	PID       int    `json:"pid"`
	Name      string `json:"name,omitempty"`
	BaseHex   string `json:"base_addr_hex"`
	BytesRead int    `json:"bytes_read"`
	SHA256    string `json:"sha256"`
}

// DeepCollectedFile is a file written during DFIR package build (response layer).
type DeepCollectedFile struct {
	Type    string
	SrcPath string
	DstPath string
	Size    int64
	SHA256  string
	Err     string
}
