//go:build windows

package collector

import (
	"path/filepath"
	"testing"
)

// Bookmark durability regression (BLUESPAWN-style EVTX discipline): every
// EvtSubscribe-backed channel must use the same read/write path as Security.
func TestEvtxBookmarkFilesRoundTrip_allChannels(t *testing.T) {
	dir := t.TempDir()
	cases := []string{
		"auth_bookmark.xml",
		"sysmon_bookmark.xml",
		"powershell_bookmark.xml",
		"defender_bookmark.xml",
		"applocker_bookmark.xml",
		"taskscheduler_bookmark.xml",
		"wmi_activity_bookmark.xml",
		"bits_client_bookmark.xml",
		"firewall_bookmark.xml",
		"system_svc_install_bookmark.xml",
	}
	want := []byte(`<BookmarkList><Bookmark Channel='Test' RecordId='42' IsCurrent='true'/></BookmarkList>`)
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			if err := writeBookmarkFile(p, want); err != nil {
				t.Fatal(err)
			}
			got, err := readBookmarkFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("bookmark mismatch for %s", name)
			}
		})
	}
}
