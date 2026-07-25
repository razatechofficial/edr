//go:build windows

package xdrclient

import "strings"

func readHardwareSerial() string {
	if out := runTrim("powershell", "-NoProfile", "-Command",
		`(Get-CimInstance -ClassName Win32_BIOS).SerialNumber`); out != "" {
		return firstNonEmptyLine(out)
	}
	if out := runTrim("wmic", "bios", "get", "serialnumber"); out != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.EqualFold(line, "SerialNumber") {
				continue
			}
			return line
		}
	}
	return ""
}

func readProductModel() string {
	if out := runTrim("powershell", "-NoProfile", "-Command",
		`(Get-CimInstance -ClassName Win32_ComputerSystem).Model`); out != "" {
		return firstNonEmptyLine(out)
	}
	return ""
}

func readManufacturer() string {
	if out := runTrim("powershell", "-NoProfile", "-Command",
		`(Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer`); out != "" {
		return firstNonEmptyLine(out)
	}
	return ""
}
