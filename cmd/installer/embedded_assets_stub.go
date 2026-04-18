//go:build !embedbundle

package main

import "io/fs"

// embeddedAssets is nil unless the installer is built with -tags embedbundle
// and cmd/installer/bundle/{models,rules}/ populated before compile.
func embeddedAssets() fs.FS {
	return nil
}
