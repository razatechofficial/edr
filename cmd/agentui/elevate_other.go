//go:build !windows

package main

import "os"

func processIsAdmin() bool { return os.Geteuid() == 0 }

func maybeElevate() error { return nil }
