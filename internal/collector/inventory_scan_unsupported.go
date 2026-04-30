//go:build !linux && !darwin && !windows

package collector

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func scanHostInventory(ctx context.Context) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out := map[string]any{}

	if h, err := os.Hostname(); err == nil {
		out["hostname"] = h
	}
	if ifs, err := net.Interfaces(); err == nil {
		out["nic_count"] = len(ifs)
	}
	if path, err := exec.LookPath("uname"); err == nil {
		b, err := exec.CommandContext(ctx, path, "-a").Output()
		if err == nil {
			out["uname_a"] = strings.TrimSpace(string(b))
		}
	}
	out["listening_socket_rows_est"] = 0
	out["listening_sockets_process_hint_rows_est"] = 0
	out["inventory_listener_attribution"] = "unavailable"

	return out, nil
}
