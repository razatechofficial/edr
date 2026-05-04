package collector

// kernelCapability captures runtime facts for kernel-tier capability reporting
// (rare GOOS probe rows and Linux/Darwin/Windows capability_probe collectors).
type kernelCapability struct {
	GOOS             string
	CGOSupported     bool
	RunningAsRoot    bool
	DtracePresent    bool
	DtracePath       string
	BPFSupported     bool
	RuntimeGoVersion string
	ReasonSummary    string
}
