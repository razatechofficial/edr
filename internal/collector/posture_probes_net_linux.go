//go:build linux

package collector

import (
	"context"
	"bufio"
	"os"
	"os/exec"
	"strings"
	"time"
)

func postureHiddenPortLinux(ctx context.Context) map[string]any {
	procN, err := countProcNetListening(ctx, "/proc/net/tcp")
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx2, "ss", "-tln").Output()
	if err != nil {
		return map[string]any{"proc_listen": procN, "ss": "unavailable", "detail": err.Error()}
	}
	ssN := 0
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "State") {
			continue
		}
		ssN++
	}
	delta := procN - ssN
	if delta < 0 {
		delta = -delta
	}
	return map[string]any{"proc_tcp_listen_rows": procN, "ss_tln_rows": ssN, "row_delta_abs": delta}
}

func countProcNetListening(ctx context.Context, path string) (int, error) {
	_ = ctx
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		st := fields[3]
		if strings.EqualFold(st, "0A") { // TCP_LISTEN in hex for some kernels — best-effort
			n++
		}
	}
	return n, sc.Err()
}

func posturePromiscInterfacesLinux(ctx context.Context) map[string]any {
	_ = ctx
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	// Promiscuous mode is not directly in /proc/net/dev; use ip link as best-effort.
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx2, "ip", "-o", "link").Output()
	if err != nil {
		return map[string]any{"proc_net_dev_bytes": len(data), "ip_link": "unavailable", "detail": err.Error()}
	}
	var promisc []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "PROMISC") {
			promisc = append(promisc, strings.TrimSpace(line))
		}
	}
	return map[string]any{"promisc_interfaces_n": len(promisc), "sample": truncateStrSlice(promisc, 6)}
}

func truncateStrSlice(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
