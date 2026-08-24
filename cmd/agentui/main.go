package main

import (
	"fmt"
	"os"
)

func main() {
	if err := maybeElevate(); err != nil {
		fmt.Fprintf(os.Stderr, "EDR Agent UI: %v\n", err)
		os.Exit(1)
	}
	if err := runDashboard(); err != nil {
		fmt.Fprintf(os.Stderr, "EDR Agent UI: %v\n", err)
		os.Exit(1)
	}
}
