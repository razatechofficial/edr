package forensics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// recordingUploader answers however the test tells it to and records what it
// was asked to ship.
type recordingUploader struct {
	calls   []Upload
	outcome func(Upload) (Outcome, error)
}

func (u *recordingUploader) Upload(_ context.Context, up Upload) (Outcome, error) {
	u.calls = append(u.calls, up)
	if u.outcome != nil {
		return u.outcome(up)
	}
	return Outcome{Stored: true, BytesStored: 1, StorageRef: "s3://test/" + up.UID}, nil
}

func accepting() *recordingUploader { return &recordingUploader{} }

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func writeStoredBundle(t *testing.T, dir, name, alertID, ruleID string, collected time.Time) string {
	t.Helper()
	stored := StoredBundle{
		Alert:     AlertTriggerMeta{AlertID: alertID, RuleID: ruleID},
		Collected: collected,
	}
	data, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return writeFile(t, dir, name, data)
}

func TestShipOnceUploadsAndMarksABundle(t *testing.T) {
	dir := t.TempDir()
	path := writeStoredBundle(t, dir, "20261009T120000Z_alert-1.json", "alert-1", "rule-7", time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
	up := accepting()
	s := NewShipper(dir, up, DefaultShipperPolicy(), nil)

	shipped, err := s.ShipOnce(context.Background())
	if err != nil {
		t.Fatalf("ship: %v", err)
	}
	if shipped != 1 {
		t.Fatalf("shipped %d bundles, expected 1", shipped)
	}
	if len(up.calls) != 1 {
		t.Fatalf("uploader called %d times", len(up.calls))
	}
	got := up.calls[0]
	if got.Path != path {
		t.Fatalf("shipped %q, expected %q", got.Path, path)
	}
	if got.AlertUID != "alert-1" || got.RuleUID != "rule-7" {
		t.Fatalf("detection metadata was not read from the bundle: %+v", got)
	}
	if got.Kind != KindArtifactBundle || got.ContentType != "application/json" {
		t.Fatalf("bundle described as kind=%q type=%q", got.Kind, got.ContentType)
	}
	if !got.CollectedAt.Equal(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("collection time %v was not taken from the bundle", got.CollectedAt)
	}
	if _, err := os.Stat(path + shippedSuffix); err != nil {
		t.Fatalf("no shipped marker was written: %v", err)
	}
	// The bundle itself stays for local triage; retention removes it later.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the bundle was removed after shipping: %v", err)
	}
}

func TestShipOnceSkipsWhatIsAlreadyShipped(t *testing.T) {
	dir := t.TempDir()
	path := writeStoredBundle(t, dir, "20261009T120000Z_alert-1.json", "alert-1", "", time.Now())
	writeFile(t, dir, filepath.Base(path)+shippedSuffix, []byte(`{}`))
	up := accepting()

	shipped, err := NewShipper(dir, up, DefaultShipperPolicy(), nil).ShipOnce(context.Background())
	if err != nil {
		t.Fatalf("ship: %v", err)
	}
	if shipped != 0 || len(up.calls) != 0 {
		t.Fatalf("a confirmed bundle was uploaded again (shipped=%d calls=%d)", shipped, len(up.calls))
	}
}

func TestShipOnceIgnoresPartialWritesAndMarkers(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "20261009T120000Z_alert-1.json.tmp", []byte(`{"alert":`))
	writeFile(t, dir, "20261009T120000Z_alert-2.json.shipped", []byte(`{}`))
	writeFile(t, dir, "empty.json", nil)
	if err := os.Mkdir(filepath.Join(dir, "a-directory"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	up := accepting()

	shipped, err := NewShipper(dir, up, DefaultShipperPolicy(), nil).ShipOnce(context.Background())
	if err != nil {
		t.Fatalf("ship: %v", err)
	}
	if shipped != 0 || len(up.calls) != 0 {
		t.Fatalf("something that is not finished evidence was shipped: %+v", up.calls)
	}
}

func TestShipOnceSendsOldestFirst(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i, name := range []string{"third.dmp", "first.dmp", "second.dmp"} {
		path := writeFile(t, dir, name, []byte(fmt.Sprintf("dump-%d", i)))
		offset := map[string]time.Duration{"first.dmp": 0, "second.dmp": time.Hour, "third.dmp": 2 * time.Hour}[name]
		when := base.Add(offset)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	up := accepting()
	if _, err := NewShipper(dir, up, DefaultShipperPolicy(), nil).ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	want := []string{"first", "second", "third"}
	if len(up.calls) != 3 {
		t.Fatalf("shipped %d bundles, expected 3", len(up.calls))
	}
	for i, uid := range want {
		if up.calls[i].UID != uid {
			t.Fatalf("position %d shipped %q, expected %q", i, up.calls[i].UID, uid)
		}
	}
}

func TestShipOnceKeepsABundleTheServerDidNotStore(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "bundle.dmp", []byte("memory"))
	up := &recordingUploader{outcome: func(Upload) (Outcome, error) {
		return Outcome{Stored: false, Message: "digest mismatch"}, nil
	}}
	s := NewShipper(dir, up, DefaultShipperPolicy(), nil)

	shipped, err := s.ShipOnce(context.Background())
	if err != nil {
		t.Fatalf("ship: %v", err)
	}
	if shipped != 0 {
		t.Fatal("a bundle the platform refused was counted as shipped")
	}
	if _, err := os.Stat(path + shippedSuffix); err == nil {
		t.Fatal("a refused bundle was marked as shipped; the only intact copy could then age out")
	}
}

func TestShipOnceStopsAfterTheAttemptCap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.dmp", []byte("memory"))
	up := &recordingUploader{outcome: func(Upload) (Outcome, error) {
		return Outcome{}, fmt.Errorf("network unreachable")
	}}
	policy := DefaultShipperPolicy()
	policy.MaxAttempts = 3
	s := NewShipper(dir, up, policy, nil)

	for i := 0; i < 6; i++ {
		if _, err := s.ShipOnce(context.Background()); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	if len(up.calls) != 3 {
		t.Fatalf("uploader called %d times, expected the cap of 3", len(up.calls))
	}
}

func TestShipOnceStopsPermanentlyWhenThePlatformHasNoUploadAPI(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.dmp", []byte("memory"))
	up := &recordingUploader{outcome: func(Upload) (Outcome, error) {
		return Outcome{}, fmt.Errorf("asking: %w", ErrUnsupported)
	}}
	s := NewShipper(dir, up, DefaultShipperPolicy(), nil)

	if _, err := s.ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if s.Enabled() {
		t.Fatal("the shipper stayed enabled after the platform said it accepts no uploads")
	}
	if _, err := s.ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if len(up.calls) != 1 {
		t.Fatalf("uploader called %d times after an unsupported answer", len(up.calls))
	}
}

func TestShipOnceRetriesAfterATransientFailure(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "bundle.dmp", []byte("memory"))
	attempt := 0
	up := &recordingUploader{outcome: func(u Upload) (Outcome, error) {
		attempt++
		if attempt == 1 {
			return Outcome{}, fmt.Errorf("connection reset")
		}
		return Outcome{Stored: true, BytesStored: 6, StorageRef: "s3://test/" + u.UID}, nil
	}}
	s := NewShipper(dir, up, DefaultShipperPolicy(), nil)

	if _, err := s.ShipOnce(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	shipped, err := s.ShipOnce(context.Background())
	if err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if shipped != 1 {
		t.Fatal("a bundle that failed once was not retried to success")
	}
	if _, err := os.Stat(path + shippedSuffix); err != nil {
		t.Fatalf("no marker after a successful retry: %v", err)
	}
}

func TestShipOnceDerivesAStableIdentifier(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "20261009T120000Z_alert-1.json", []byte(`{}`))
	up := accepting()
	s := NewShipper(dir, up, DefaultShipperPolicy(), nil)

	if _, err := s.ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	// Remove the marker so the same file is offered again: the identifier must
	// not change, or the platform would store a second copy.
	if err := os.Remove(filepath.Join(dir, "20261009T120000Z_alert-1.json"+shippedSuffix)); err != nil {
		t.Fatalf("remove marker: %v", err)
	}
	if _, err := s.ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship again: %v", err)
	}
	if len(up.calls) != 2 {
		t.Fatalf("uploader called %d times", len(up.calls))
	}
	if up.calls[0].UID != up.calls[1].UID {
		t.Fatalf("the same file produced two identifiers: %q and %q", up.calls[0].UID, up.calls[1].UID)
	}
	if up.calls[0].UID != "20261009T120000Z_alert-1" {
		t.Fatalf("identifier %q does not come from the filename", up.calls[0].UID)
	}
}

func TestShipperKindAndContentTypeFollowTheExtension(t *testing.T) {
	cases := map[string][2]string{
		"a.json": {KindArtifactBundle, "application/json"},
		"a.dmp":  {KindMemoryDump, "application/octet-stream"},
		"a.raw":  {KindMemoryDump, "application/octet-stream"},
		"a.zip":  {KindDFIRPackage, "application/zip"},
		"a.tgz":  {KindDFIRPackage, "application/gzip"},
		"a.bin":  {KindDFIRPackage, "application/octet-stream"},
	}
	for name, want := range cases {
		if got := kindFromName(name); got != want[0] {
			t.Errorf("%s: kind %q, expected %q", name, got, want[0])
		}
		if got := contentTypeFromName(name); got != want[1] {
			t.Errorf("%s: content type %q, expected %q", name, got, want[1])
		}
	}
}

func TestShipOnceIsANoOpWithoutAnUploader(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.dmp", []byte("memory"))
	s := NewShipper(dir, nil, DefaultShipperPolicy(), nil)
	if s.Enabled() {
		t.Fatal("a shipper with no uploader reported itself enabled")
	}
	if shipped, err := s.ShipOnce(context.Background()); err != nil || shipped != 0 {
		t.Fatalf("ship with no uploader: shipped=%d err=%v", shipped, err)
	}
}

func TestShipOnceToleratesAMissingDirectory(t *testing.T) {
	s := NewShipper(filepath.Join(t.TempDir(), "absent"), accepting(), DefaultShipperPolicy(), nil)
	if shipped, err := s.ShipOnce(context.Background()); err != nil || shipped != 0 {
		t.Fatalf("shipped=%d err=%v", shipped, err)
	}
}

func TestReadBundleMetaIsBounded(t *testing.T) {
	dir := t.TempDir()
	// A file far larger than the metadata bound, whose JSON only completes past
	// it: the read must give up rather than consume the whole file.
	padding := make([]byte, 2<<20)
	for i := range padding {
		padding[i] = 'x'
	}
	body := append([]byte(`{"alert":{"alert_id":"a"},"blob":"`), padding...)
	body = append(body, []byte(`"}`)...)
	path := writeFile(t, dir, "huge.json", body)
	if _, ok := readBundleMeta(path); ok {
		t.Fatal("a file larger than the metadata bound was decoded in full")
	}
}
