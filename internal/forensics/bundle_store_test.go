package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleBundle() *ArtifactBundle {
	return &ArtifactBundle{Hostname: "host-a", OS: "linux"}
}

// The collection used to be assigned to _ and dropped. The host had already
// been scanned; the only product was the belief that evidence existed.
func TestABundleIsWrittenAndDigested(t *testing.T) {
	dir := t.TempDir()
	meta := AlertTriggerMeta{AlertID: "alert-123", RuleID: "SIGMA-1", EndpointID: "ep-9"}

	res, err := WriteBundle(dir, meta, sampleBundle())
	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	data, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("the bundle was not written: %v", err)
	}
	if res.Bytes != int64(len(data)) {
		t.Errorf("Bytes = %d, file is %d", res.Bytes, len(data))
	}
	// The digest must match the bytes on disk, or it is worthless as the start
	// of a chain of custody.
	sum := sha256.Sum256(data)
	if res.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("the recorded digest does not match the file")
	}
}

func TestTheAlertTravelsWithTheEvidence(t *testing.T) {
	dir := t.TempDir()
	meta := AlertTriggerMeta{AlertID: "alert-123", RuleID: "SIGMA-1", EndpointID: "ep-9", Severity: "high"}

	res, err := WriteBundle(dir, meta, sampleBundle())
	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	var stored StoredBundle
	raw, _ := os.ReadFile(res.Path)
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stored.Alert.AlertID != "alert-123" || stored.Alert.RuleID != "SIGMA-1" {
		t.Errorf("a bundle that cannot name its detection: %+v", stored.Alert)
	}
	if stored.Bundle == nil || stored.Bundle.Hostname != "host-a" {
		t.Error("the bundle itself was lost")
	}
	if stored.Collected.IsZero() {
		t.Error("no collection time recorded")
	}
}

// Alert and rule identifiers come from detection content, which is not
// necessarily well-behaved, and they are used to build a filename.
func TestHostileIdentifiersCannotEscapeTheDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{
		"../../etc/passwd",
		"..\\..\\windows\\system32\\x",
		"a/b/c",
		strings.Repeat("x", 300),
		"",
		"   ",
	} {
		res, err := WriteBundle(dir, AlertTriggerMeta{AlertID: id}, sampleBundle())
		if err != nil {
			t.Fatalf("id %q: %v", id, err)
		}
		if filepath.Dir(res.Path) != dir {
			t.Errorf("id %q escaped to %s", id, res.Path)
		}
	}
}

func TestBundlesAreNotWorldReadable(t *testing.T) {
	// A bundle carries process arguments, environment variables and file paths
	// captured at the moment of a detection.
	dir := t.TempDir()
	res, err := WriteBundle(dir, AlertTriggerMeta{AlertID: "a"}, sampleBundle())
	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	info, err := os.Stat(res.Path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("mode = %04o, want no group or other access", perm)
	}
}

func TestMissingInputsAreRefusedNotSilentlySkipped(t *testing.T) {
	if _, err := WriteBundle(t.TempDir(), AlertTriggerMeta{}, nil); err == nil {
		t.Error("a nil bundle was accepted")
	}
	if _, err := WriteBundle("", AlertTriggerMeta{}, sampleBundle()); err == nil {
		t.Error("an unconfigured directory was accepted")
	}
}

func TestNoPartialFileIsLeftBehind(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteBundle(dir, AlertTriggerMeta{AlertID: "a"}, sampleBundle()); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file survived: %s", e.Name())
		}
	}
}
