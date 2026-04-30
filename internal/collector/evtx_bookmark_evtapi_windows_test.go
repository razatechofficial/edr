//go:build windows

package collector

import (
	"path/filepath"
	"testing"

	"github.com/razatechofficial/edr/internal/kernel"
	"golang.org/x/sys/windows"
)

// Validates EvtSaveBookmark → file → EvtLoadBookmark parity (G-BLS-MATRIX depth).
func TestEvtBookmarkSaveLoadRoundTrip_evtAPI(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "roundtrip_bm.xml")

	h, err := kernel.EvtCreateBookmark(nil)
	if err != nil {
		t.Skipf("EvtCreateBookmark: %v", err)
		return
	}
	defer kernel.EvtClose(h)

	pathU16, err := windows.UTF16PtrFromString(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := kernel.EvtSaveBookmark(h, pathU16); err != nil {
		t.Fatalf("EvtSaveBookmark: %v", err)
	}

	h2, err := kernel.EvtLoadBookmark(pathU16)
	if err != nil {
		t.Fatalf("EvtLoadBookmark: %v", err)
	}
	defer kernel.EvtClose(h2)
}
