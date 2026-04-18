//go:build embedbundle

package main

import (
	"embed"
	"io/fs"
)

// Populated at compile time from cmd/installer/bundle/models and .../rules
// (see Makefile target build-installer-embedded).
//
//go:embed all:bundle
var embeddedBundleRoot embed.FS

func embeddedAssets() fs.FS {
	return embeddedBundleRoot
}
