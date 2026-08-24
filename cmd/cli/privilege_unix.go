//go:build !windows

package main

import "os"

func processPrivileged() bool { return os.Geteuid() == 0 }

func privilegeDeniedMessage() string {
	return "this command requires root; re-run with sudo"
}
