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
			os.Exit(hostperm.RunFDAProbe())
		}
		if a == "--register-service" {
			if err := hostperm.EnsureSensorService("", ""); err != nil {
				fmt.Fprintf(os.Stderr, "register service: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		if a == "--setup" {
			fmt.Fprintf(os.Stderr, "custom Setup UI removed — install with the native OS package (MSI/pkg/deb)\n")
			os.Exit(2)
		}
		if a == "--tray" {
			flagTray = true
		}
		if a == "-h" || a == "--help" {
			fmt.Fprintf(os.Stdout, "edr\n  --tray    menu bar only (login item; window stays hidden until opened)\n")
			os.Exit(0)
		}
	}
	if runningAttendedSetup() {
		fmt.Fprintf(os.Stderr, "EDR-Agent-Setup is retired — use the native OS package (MSI/pkg/deb)\n")
		os.Exit(2)
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
