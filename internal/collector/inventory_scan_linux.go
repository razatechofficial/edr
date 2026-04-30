//go:build linux

package collector

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

func scanHostInventory(ctx context.Context) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out := map[string]any{}

	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		out["os_release"] = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		out["boot_id"] = strings.TrimSpace(string(b))
	}
	if b, err := exec.CommandContext(ctx, "uname", "-r").Output(); err == nil {
		out["kernel_release"] = strings.TrimSpace(string(b))
	}

	pkgCount := 0
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		c := exec.CommandContext(ctx, "sh", "-c", "dpkg-query -f '${Package}\n' -W 2>/dev/null | wc -l")
		if b, err := c.Output(); err == nil {
			pkgCount = atoiTrim(string(b))
		}
	}
	if pkgCount == 0 {
		if _, err := exec.LookPath("rpm"); err == nil {
			c := exec.CommandContext(ctx, "sh", "-c", "rpm -qa 2>/dev/null | wc -l")
			if b, err := c.Output(); err == nil {
				pkgCount = atoiTrim(string(b))
			}
		}
	}
	snapCount := 0
	if _, err := exec.LookPath("snap"); err == nil {
		c := exec.CommandContext(ctx, "sh", "-c", "snap list 2>/dev/null | tail -n +2 | wc -l")
		if b, err := c.Output(); err == nil {
			snapCount = atoiTrim(string(b))
		}
	}
	out["package_count_est"] = pkgCount
	out["snap_package_count_est"] = snapCount

	listenerRows := 0
	pidHintRows := 0
	attrib := "unavailable"
	if _, err := exec.LookPath("ss"); err == nil {
		b, errUp := exec.CommandContext(ctx, "ss", "-lntup").Output()
		if errUp == nil {
			text := string(b)
			listenerRows, pidHintRows = parseSsListenerStats(text)
			if listenerRows == 0 && strings.TrimSpace(text) != "" {
				if n := countNonEmptyLines(text) - 1; n > 0 {
					listenerRows = n
				}
			}
			if pidHintRows > 0 {
				attrib = "full"
			} else if listenerRows > 0 {
				attrib = "partial"
			}
		}
		if attrib == "unavailable" {
			b2, errTu := exec.CommandContext(ctx, "ss", "-lntu").Output()
			if errTu == nil {
				text2 := string(b2)
				listenerRows, pidHintRows = parseSsListenerStats(text2)
				if listenerRows == 0 && strings.TrimSpace(text2) != "" {
					if n := countNonEmptyLines(text2) - 1; n > 0 {
						listenerRows = n
					}
				}
				pidHintRows = 0
				attrib = "count_only"
			}
		}
	}
	out["listening_socket_rows_est"] = listenerRows
	out["listening_sockets_process_hint_rows_est"] = pidHintRows
	out["inventory_listener_attribution"] = attrib

	return out, nil
}
