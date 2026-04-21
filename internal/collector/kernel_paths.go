package collector

// BPFObjectInstallPath is the default path for the packaged eBPF object on Linux installs.
func BPFObjectInstallPath() string {
	return "/var/lib/edr/bpf/edr.bpf.o"
}
