//go:build windows

package forensics

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func collectAmcacheWindows(cfg *ForensicsDeepConfig, bundle *DeepArtifactsBundle) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	src := filepath.Join(root, "AppCompat", "Programs", "Amcache.hve")
	dstDir := filepath.Join(cfg.WorkDir, "amcache")
	// Open source with share read to avoid locking the live hive.
	pathPtr, err := windows.UTF16PtrFromString(src)
	if err != nil {
		bundle.AmcacheError = err.Error()
		return
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		bundle.AmcacheError = err.Error()
		return
	}
	_ = windows.CloseHandle(h)

	ent, err := copyFileBounded(src, dstDir, "Amcache.hve", 256<<20)
	if err != nil && ent.Note == "" {
		ent.Note = err.Error()
	}
	if err != nil {
		bundle.AmcacheError = err.Error()
	}
	bundle.Amcache = &ent
}
