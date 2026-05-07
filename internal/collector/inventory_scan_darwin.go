//go:build darwin

package collector

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func scanHostInventory(ctx context.Context) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out := map[string]any{}

	if b, err := exec.CommandContext(ctx, "sw_vers").Output(); err == nil {
		out["sw_vers"] = strings.TrimSpace(string(b))
	}
	if b, err := exec.CommandContext(ctx, "uname", "-r").Output(); err == nil {
		out["kernel_release"] = strings.TrimSpace(string(b))
	}

	pkgLines := 0
	if b, err := exec.CommandContext(ctx, "sh", "-c", "pkgutil --pkgs 2>/dev/null | wc -l").Output(); err == nil {
		pkgLines = atoiTrim(string(b))
	}
	out["pkgutil_package_lines_est"] = pkgLines

	// Prefer lsof TCP listeners (process column) — mirrors Linux attribution story.
	listenerRows, pidHints, attrib := 0, 0, "unavailable"
	if _, err := exec.LookPath("lsof"); err == nil {
		c := exec.CommandContext(ctx, "lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
		b, err := c.Output()
		if err == nil {
			listenerRows, pidHints = parseDarwinLsofListen(string(b))
			switch {
			case pidHints > 0:
				attrib = "full"
			case listenerRows > 0:
				attrib = "partial"
			default:
				attrib = "partial"
			}
			out["listening_socket_rows_est"] = listenerRows
			out["listening_sockets_process_hint_rows_est"] = pidHints
			out["inventory_listener_attribution"] = attrib
		}
	}
	if attrib == "unavailable" {
		if b, err := exec.CommandContext(ctx, "sh", "-c", "netstat -an -p tcp 2>/dev/null | wc -l").Output(); err == nil {
			netLines := atoiTrim(string(b))
			out["netstat_tcp_lines_est"] = netLines
			out["inventory_listener_attribution"] = "count_only"
		}
	}

	if b, err := exec.CommandContext(ctx, "dscl", ".", "list", "/Users").Output(); err == nil {
		out["dscl_users_lines_est"] = countNonEmptyLines(string(b))
	}

	return out, nil
}

// parseDarwinLsofListen counts LISTEN rows and rows with a numeric PID (field 2).
func parseDarwinLsofListen(text string) (listenRows int, pidHintRows int) {
	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if i == 0 && strings.Contains(strings.ToUpper(line), "COMMAND") {
			continue
		}
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		listenRows++
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if _, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
				pidHintRows++
			}
		}
	}
	return listenRows, pidHintRows
}
