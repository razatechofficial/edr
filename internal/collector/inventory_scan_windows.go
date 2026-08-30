//go:build windows

package collector

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func scanHostInventory(ctx context.Context) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out := map[string]any{}

	ps := func(script string) string {
		c := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		hideConsole(c)
		b, err := c.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}

	if s := ps("(Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).Version"); s != "" {
		out["windows_os"] = s
	}
	if s := ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').BuildLabEx"); s != "" {
		out["build_lab_ex"] = s
	}

	prog := ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object DisplayName).Count")
	if prog != "" {
		out["installed_program_registry_rows"] = atoiTrim(prog)
	}

	svcTotal := ps("(Get-Service -ErrorAction SilentlyContinue | Measure-Object).Count")
	if svcTotal != "" {
		out["windows_services_total"] = atoiTrim(svcTotal)
	}
	svcRun := ps("(@(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }).Count)")
	if svcRun != "" {
		out["windows_services_running"] = atoiTrim(svcRun)
	}
	if s := ps("(Get-LocalUser -ErrorAction SilentlyContinue | Measure-Object).Count"); s != "" {
		out["local_user_count_est"] = atoiTrim(s)
	}

	lr, pidOwn := windowsListenMIBRowCounts()
	out["listening_socket_rows_est"] = lr
	out["listening_sockets_process_hint_rows_est"] = pidOwn
	out["inventory_listener_attribution"] = inventoryListenerAttributionMIB(lr, pidOwn)

	return out, nil
}
