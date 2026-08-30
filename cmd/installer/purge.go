package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func extraPurgeTrees() []string {
	return extraPurgeTreesFor(platformPaths())
}

func removeInstanceLocks() {
	dir := os.TempDir()
	for _, name := range []string{
		"com.razatech.edr.console.port",
		"com.razatech.edr.setup.port",
	} {
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			fmt.Printf("    warning: %s: %v\n", p, err)
		}
	}
}

func purgeTrees(dirs []string) {
	for _, dir := range dirs {
		if stringsBlankOrRoot(dir) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
			fmt.Printf("    warning: removing %s: %v\n", dir, err)
		} else if err == nil {
			fmt.Printf("    removed %s\n", dir)
		}
	}
}

func stringsBlankOrRoot(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return true
	}
	s := filepath.Clean(dir)
	if s == "." || s == "/" || s == `\` {
		return true
	}
	vol := filepath.VolumeName(s)
	return vol != "" && (s == vol || s == vol+`\` || s == vol+`/`)
}
