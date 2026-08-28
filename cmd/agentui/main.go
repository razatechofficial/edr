package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/razatechofficial/edr/internal/hostperm"
)

var flagSetup bool
var flagTray bool

func main() {
	for _, a := range os.Args[1:] {
		if a == "--fda-probe" || a == "fda-probe" {
			if hostperm.ProcessHasFDA() {
				os.Exit(0)
			}
			os.Exit(1)
		}
		if a == "--setup" {
			flagSetup = true
		}
		if a == "--tray" {
			flagTray = true
		}
		if a == "-h" || a == "--help" {
			fmt.Fprintf(os.Stdout, "edr\n  --setup   attended installer (EULA, copy files, then enroll)\n  --tray    menu bar only (login item; window stays hidden until opened)\n")
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
