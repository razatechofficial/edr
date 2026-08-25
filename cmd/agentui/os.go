package main

import "runtime"

func isDarwin() bool  { return runtime.GOOS == "darwin" }
func isWindows() bool { return runtime.GOOS == "windows" }
func isLinux() bool   { return runtime.GOOS == "linux" }
