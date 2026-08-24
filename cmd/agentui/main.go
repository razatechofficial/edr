package main

import (
	"fmt"
	"os"
)

func main() {
	if err := runGUI(); err != nil {
		fmt.Fprintf(os.Stderr, "EDR Agent UI: %v\n", err)
		os.Exit(1)
	}
}
