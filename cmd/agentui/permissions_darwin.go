//go:build darwin

package main

import (
	"os"
	"os/exec"
)

func needsFullDiskAccess() bool { return true }

func hasFullDiskAccess() bool {
	paths := []string{
		"/Library/Application Support/com.apple.TCC/TCC.db",
		"/var/db/locationd/clients.plist",
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err == nil {
			_ = f.Close()
			return true
		}
	}
	return false
}

func openFullDiskAccessSettings() error {
	urls := []string{
		"x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles",
		"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
	}
	var last error
	for _, u := range urls {
		last = exec.Command("/usr/bin/open", u).Start()
		if last == nil {
			return nil
		}
	}
	return last
}

func openOSGrantSettings() error { return openFullDiskAccessSettings() }
