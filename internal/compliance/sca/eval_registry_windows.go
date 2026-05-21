//go:build windows

package sca

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func evalRegistryRule(keyPath, pattern string) (bool, error) {
	keyPath = strings.TrimSpace(keyPath)
	if keyPath == "" {
		return false, fmt.Errorf("sca: empty registry path")
	}
	valueName, expectPattern := parseRegistryPattern(pattern)
	hive, subKey := splitHive(keyPath)
	var hiveKey registry.Key
	switch strings.ToUpper(hive) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hiveKey = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		hiveKey = registry.CURRENT_USER
	case "HKU", "HKEY_USERS":
		hiveKey = registry.USERS
	default:
		return false, fmt.Errorf("sca: unsupported registry hive %q", hive)
	}
	k, err := registry.OpenKey(hiveKey, subKey, registry.READ)
	if err != nil {
		if expectPattern == "" {
			return false, nil
		}
		return matchContent("", expectPattern)
	}
	defer k.Close()
	if valueName == "" {
		return true, nil
	}
	val, _, err := k.GetStringValue(valueName)
	if err != nil {
		return matchContent("", expectPattern)
	}
	return matchContent(val, expectPattern)
}

func splitHive(keyPath string) (hive, subKey string) {
	sep := strings.Index(keyPath, `\`)
	if sep < 0 {
		return keyPath, ""
	}
	return keyPath[:sep], keyPath[sep+1:]
}

func parseRegistryPattern(pattern string) (valueName, expect string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return "", ""
	}
	idx := strings.Index(pattern, ruleSep)
	if idx < 0 {
		return pattern, ""
	}
	return strings.TrimSpace(pattern[:idx]), strings.TrimSpace(pattern[idx+len(ruleSep):])
}
