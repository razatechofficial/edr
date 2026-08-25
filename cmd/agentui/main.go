package main

import (
	"fmt"
	"os"
	"runtime"
)

var flagSetup bool

func main() {
	for _, a := range os.Args[1:] {
		if a == "--setup" {
			flagSetup = true
		}
		if a == "-h" || a == "--help" {
			fmt.Fprintf(os.Stdout, "EDR Agent\n  --setup   attended installer (EULA, copy files, then enroll)\n")
			os.Exit(0)
		}
	}
	if err := maybeElevate(); err != nil {
		fmt.Fprintf(os.Stderr, "EDR Agent UI: %v\n", err)
		os.Exit(1)
	}
	if runtime.GOOS == "linux" {
		if err := runLinuxTUI(); err != nil {
			fmt.Fprintf(os.Stderr, "EDR Agent: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := runDashboard(); err != nil {
		fmt.Fprintf(os.Stderr, "EDR Agent UI: %v\n", err)
		os.Exit(1)
	}
}
