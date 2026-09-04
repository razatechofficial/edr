//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "svcreg is Windows-only")
	os.Exit(2)
}
