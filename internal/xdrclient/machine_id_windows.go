//go:build windows

package xdrclient

import (
	"strings"
)

// platformSystemUUID returns Win32_ComputerSystemProduct.UUID (SMBIOS Type 1 UUID).
func platformSystemUUID() string {
	// Prefer CIM/PowerShell; fall back to legacy wmic when available.
	if out := runTrim("powershell", "-NoProfile", "-Command",
		`(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID`); out != "" {
		return firstNonEmptyLine(out)
	}
	if out := runTrim("wmic", "csproduct", "get", "UUID"); out != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.EqualFold(line, "UUID") {
				continue
			}
			return line
		}
	}
	return ""
}
