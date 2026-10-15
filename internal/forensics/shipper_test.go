package forensics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestReadBundleMetaReadsAttributionAheadOfAHugeBody(t *testing.T) {
	dir := t.TempDir()
	// The body is far past the read limit. The attribution comes first, so it
	// is read and the rest is never touched. This used to return nothing at
	// all: decoding into a struct needs the whole document to parse, so it
	// failed with an unexpected EOF at the limit — and a memory dump bundle is
	// routinely larger than the limit, so that was most of them.
	padding := strings.Repeat("x", 2<<20)
	body := `{"alert":{"alert_id":"a1","rule_id":"r1"},"collected_at":"2026-10-13T09:00:00Z","bundle":{"blob":"` + padding + `"}}`
	path := writeFile(t, dir, "huge.json", []byte(body))

	meta, ok := readBundleMeta(path)
	if !ok {
		t.Fatal("attribution was not read from a bundle larger than the read limit")
	}
	if meta.Alert.AlertID != "a1" || meta.Alert.RuleID != "r1" {
		t.Fatalf("attribution %+v", meta.Alert)
	}
	if meta.Collected.IsZero() {
		t.Fatal("collection time was not read")
	}
}

func TestReadBundleMetaGivesUpOnAFileWithNoAttribution(t *testing.T) {
	dir := t.TempDir()
	// A file in this directory need not be one of ours. With no attribution at
	// the front, stepping over the body runs into the read limit and the read
	// gives up rather than walking a multi-gigabyte file.
	body := `{"blob":"` + strings.Repeat("x", 2<<20) + `","alert":{"alert_id":"too-late"}}`
	path := writeFile(t, dir, "foreign.json", []byte(body))

	if _, ok := readBundleMeta(path); ok {
		t.Fatal("a file whose attribution sits past the read limit was reported as attributed")
	}
}

func TestReadBundleMetaRejectsWhatIsNotAJSONObject(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"array.json":     `[{"alert":{"alert_id":"a"}}]`,
		"scalar.json":    `"just a string"`,
		"truncated.json": `{"alert":{"alert_id":`,
		"empty.json":     `   `,
	} {
		path := writeFile(t, dir, name, []byte(body))
		if _, ok := readBundleMeta(path); ok {
			t.Errorf("%s was accepted as a bundle", name)
		}
	}
}

func TestSkipJSONValueStepsOverNestedStructures(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"a":{"b":[1,2,{"c":3}]},"d":7}`))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("opening token: %v %v", tok, err)
	}
	// Step over "a" and its whole nested value, then confirm the decoder is
	// positioned on "d" rather than somewhere inside what was skipped.
	if _, err := dec.Token(); err != nil {
		t.Fatalf("key token: %v", err)
	}
	if err := skipJSONValue(dec); err != nil {
		t.Fatalf("skip: %v", err)
	}
	keyTok, err := dec.Token()
	if err != nil {
		t.Fatalf("next key: %v", err)
	}
	if key, _ := keyTok.(string); key != "d" {
		t.Fatalf("decoder landed on %q, expected \"d\"", key)
	}
}

func TestSkipJSONValueReportsATruncatedValue(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"a":{"b":`))
	if _, err := dec.Token(); err != nil {
		t.Fatalf("opening token: %v", err)
	}
	if _, err := dec.Token(); err != nil {
		t.Fatalf("key token: %v", err)
	}
	if err := skipJSONValue(dec); err == nil {
		t.Fatal("a truncated value was skipped without error, so a bounded read would look complete")
	}
}

func TestShipOnceHoldsEvidenceWhenTheAllowanceIsSpent(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "bundle.dmp", []byte("memory"))
	up := &recordingUploader{outcome: func(Upload) (Outcome, error) {
		return Outcome{}, fmt.Errorf("refused: %w", ErrOverBudget)
	}}
	policy := DefaultShipperPolicy()
	policy.MaxAttempts = 3
	policy.BudgetBackoff = time.Hour
	s := NewShipper(dir, up, policy, nil)

	for i := 0; i < 5; i++ {
		if _, err := s.ShipOnce(context.Background()); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	// One attempt, then nothing: retrying every cycle would spend the
	// endpoint's bandwidth being refused.
	if len(up.calls) != 1 {
		t.Fatalf("uploader called %d times while the allowance was spent, expected 1", len(up.calls))
	}
	// The bundle stays on disk, unmarked, so it ships once the allowance
	// refills.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the bundle was removed: %v", err)
	}
	if _, err := os.Stat(path + shippedSuffix); err == nil {
		t.Fatal("a bundle that was never stored was marked as shipped")
	}
	// The shipper stays enabled: unlike an unsupported platform, this clears.
	if !s.Enabled() {
		t.Fatal("the shipper disabled itself over a spent allowance")
	}
}

func TestASpentAllowanceDoesNotBurnTheAttemptCap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.dmp", []byte("memory"))
	refusals := 0
	up := &recordingUploader{outcome: func(u Upload) (Outcome, error) {
		refusals++
		if refusals == 1 {
			return Outcome{}, fmt.Errorf("refused: %w", ErrOverBudget)
		}
		return Outcome{Stored: true, BytesStored: 6, StorageRef: "s3://t/" + u.UID}, nil
	}}
	policy := DefaultShipperPolicy()
	policy.MaxAttempts = 1
	policy.BudgetBackoff = time.Hour
	s := NewShipper(dir, up, policy, nil)

	if _, err := s.ShipOnce(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	// Pretend the hold has elapsed. With MaxAttempts of 1, a budget refusal
	// that counted as an attempt would have abandoned this bundle for good.
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	shipped, err := s.ShipOnce(context.Background())
	if err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if shipped != 1 {
		t.Fatal("a bundle refused on allowance grounds was abandoned rather than retried")
	}
}

func TestTheHoldClearsOnceItHasElapsed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bundle.dmp", []byte("memory"))
	up := &recordingUploader{outcome: func(Upload) (Outcome, error) {
		return Outcome{}, fmt.Errorf("refused: %w", ErrOverBudget)
	}}
	policy := DefaultShipperPolicy()
	policy.BudgetBackoff = 30 * time.Minute
	s := NewShipper(dir, up, policy, nil)

	if _, err := s.ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if s.heldUntil().IsZero() {
		t.Fatal("no hold was set after a spent allowance")
	}
	s.now = func() time.Time { return time.Now().Add(time.Hour) }
	if !s.heldUntil().IsZero() {
		t.Fatal("the hold did not clear after it elapsed")
	}
	if _, err := s.ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship after the hold: %v", err)
	}
	if len(up.calls) != 2 {
		t.Fatalf("uploader called %d times, expected a second attempt after the hold", len(up.calls))
	}
}

func TestBudgetBackoffFallsBackToADefault(t *testing.T) {
	policy := ShipperPolicy{BudgetBackoff: 0}
	s := NewShipper(t.TempDir(), accepting(), policy, nil)
	if s.policy.BudgetBackoff != DefaultShipperPolicy().BudgetBackoff {
		t.Fatalf("backoff %v", s.policy.BudgetBackoff)
	}
}

func TestABundleLargerThanTheMetadataBoundIsStillAttributed(t *testing.T) {
	dir := t.TempDir()
	// A bundle whose body is comfortably past the one-megabyte window the
	// shipper reads to find the alert. StoredBundle puts the alert before the
	// body, so this works; moving the body first would silently strip
	// attribution from every large bundle.
	padding := make([]FileRecord, 0, 8000)
	for i := 0; i < 8000; i++ {
		padding = append(padding, FileRecord{
			Path:   fmt.Sprintf("/tmp/padding-%06d-%s.bin", i, strings.Repeat("x", 120)),
			SHA256: strings.Repeat("a", 64),
		})
	}
	meta := AlertTriggerMeta{AlertID: "alert-large", RuleID: "rule-large"}
	res, err := WriteBundle(dir, meta, &ArtifactBundle{
		Timestamp: time.Now().UTC(),
		File:      &FileArtifacts{TempRecords: padding},
	})
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if res.Bytes < 1<<20 {
		t.Fatalf("the test bundle is only %d bytes; it does not exercise the bound", res.Bytes)
	}

	up := accepting()
	if _, err := NewShipper(dir, up, DefaultShipperPolicy(), nil).ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if len(up.calls) != 1 {
		t.Fatalf("uploader called %d times", len(up.calls))
	}
	if up.calls[0].AlertUID != "alert-large" {
		t.Fatalf("alert attribution lost on a large bundle: %q", up.calls[0].AlertUID)
	}
	if up.calls[0].RuleUID != "rule-large" {
		t.Fatalf("rule attribution lost on a large bundle: %q", up.calls[0].RuleUID)
	}
}

func TestStoredBundlePutsAttributionBeforeTheBody(t *testing.T) {
	// Asserted on the encoding rather than through the shipper, so a reordering
	// of StoredBundle fails here with a clear reason rather than as a confusing
	// loss of attribution somewhere downstream.
	data, err := json.Marshal(StoredBundle{
		Alert:     AlertTriggerMeta{AlertID: "a"},
		Collected: time.Now().UTC(),
		Bundle:    &ArtifactBundle{Hostname: "h"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := string(data)
	alertAt := strings.Index(encoded, `"alert"`)
	bundleAt := strings.Index(encoded, `"bundle"`)
	if alertAt < 0 || bundleAt < 0 {
		t.Fatalf("encoding does not carry both fields: %s", encoded[:80])
	}
	if alertAt > bundleAt {
		t.Fatal("the bundle body is encoded before its alert; the shipper reads only the first megabyte, so large bundles would lose attribution")
	}
}

// writeDump lays out a memory dump the way the memory handler does: the
// compressed capture, plus a sidecar holding the detection it belongs to.
func writeDump(t *testing.T, dir, base, alertID string, captured time.Time) (dump, sidecar string) {
	t.Helper()
	dump = writeFile(t, dir, base+".gz", []byte("compressed memory"))
	meta := map[string]any{
		"pid":          4242,
		"process_name": "evil.exe",
		"dump_path":    dump,
		"platform":     "linux",
		"captured_at":  captured.UTC().Format(time.RFC3339Nano),
		"alert_id":     alertID,
		"modules":      []string{"libc.so.6"},
	}
	body, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal sidecar: %v", err)
	}
	sidecar = writeFile(t, dir, base+".meta.json", body)
	return dump, sidecar
}

func TestAMemoryDumpIsClassifiedAndAttributed(t *testing.T) {
	dir := t.TempDir()
	captured := time.Date(2026, 10, 13, 9, 30, 0, 0, time.UTC)
	writeDump(t, dir, "memdump_4242_20261013T093000Z", "alert-mem", captured)

	up := accepting()
	if _, err := NewShipper(dir, up, DefaultShipperPolicy(), nil).ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if len(up.calls) != 2 {
		t.Fatalf("shipped %d files, expected the dump and its sidecar", len(up.calls))
	}

	byKind := map[string]Upload{}
	for _, c := range up.calls {
		byKind[c.Kind] = c
	}
	dump, ok := byKind[KindMemoryDump]
	if !ok {
		// A dump is written compressed, and encrypted when a key is set, so
		// going by extension filed every one as a generic package.
		t.Fatalf("the dump was not classified as a memory dump: %+v", up.calls)
	}
	// The most expensive evidence the agent collects must not arrive naming no
	// detection.
	if dump.AlertUID != "alert-mem" {
		t.Fatalf("the dump was shipped with alert %q", dump.AlertUID)
	}
	if !dump.CollectedAt.Equal(captured) {
		t.Fatalf("the dump's capture time %v did not come from the sidecar", dump.CollectedAt)
	}
	if dump.ContentType != "application/gzip" {
		t.Fatalf("dump content type %q", dump.ContentType)
	}

	side, ok := byKind[KindArtifactBundle]
	if !ok {
		t.Fatalf("the sidecar was not shipped: %+v", up.calls)
	}
	// The sidecar is evidence too: the module list is recorded nowhere else.
	if side.AlertUID != "alert-mem" {
		t.Fatalf("the sidecar was shipped with alert %q", side.AlertUID)
	}
}

func TestAnEncryptedDumpIsStillClassifiedAsMemory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "memdump_1_20261013T093000Z.gz.enc", []byte("ciphertext"))
	up := accepting()
	if _, err := NewShipper(dir, up, DefaultShipperPolicy(), nil).ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if len(up.calls) != 1 || up.calls[0].Kind != KindMemoryDump {
		t.Fatalf("calls: %+v", up.calls)
	}
}

func TestADumpAndItsSidecarGetDifferentIdentifiers(t *testing.T) {
	dir := t.TempDir()
	writeDump(t, dir, "memdump_7_20261013T093000Z", "alert-x", time.Now())
	up := accepting()
	if _, err := NewShipper(dir, up, DefaultShipperPolicy(), nil).ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if len(up.calls) != 2 {
		t.Fatalf("%d calls", len(up.calls))
	}
	// The platform's ledger is keyed on tenant and bundle identifier alone, so
	// two files sharing one would make the second be answered "already stored"
	// and never uploaded.
	if up.calls[0].UID == up.calls[1].UID {
		t.Fatalf("the dump and its sidecar share the identifier %q", up.calls[0].UID)
	}
}

func TestSidecarForFindsTheMetadataBesideADump(t *testing.T) {
	cases := map[string]string{
		"/f/memdump_1_TS.gz":     "/f/memdump_1_TS.meta.json",
		"/f/memdump_1_TS.gz.enc": "/f/memdump_1_TS.meta.json",
		"/f/memdump_1_TS":        "/f/memdump_1_TS.meta.json",
	}
	for dump, want := range cases {
		if got := sidecarFor(dump); got != want {
			t.Errorf("sidecarFor(%q) = %q, expected %q", dump, got, want)
		}
	}
}

func TestADumpWithNoSidecarStillShips(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "memdump_9_20261013T093000Z.gz", []byte("orphan"))
	up := accepting()
	if _, err := NewShipper(dir, up, DefaultShipperPolicy(), nil).ShipOnce(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	// Unattributed evidence off the host still beats evidence lost with it.
	if len(up.calls) != 1 {
		t.Fatalf("%d calls", len(up.calls))
	}
	if up.calls[0].AlertUID != "" {
		t.Fatalf("an alert was invented: %q", up.calls[0].AlertUID)
	}
}

func TestReadDumpSidecarRejectsWhatIsNotOne(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "notasidecar.meta.json", []byte(`{"unrelated":"fields"}`))
	if _, _, _, ok := readDumpSidecar(path); ok {
		t.Fatal("a file with no attribution was accepted as a sidecar")
	}
	missing := filepath.Join(dir, "absent.meta.json")
	if _, _, _, ok := readDumpSidecar(missing); ok {
		t.Fatal("a missing sidecar was accepted")
	}
}

func TestMemoryDumpKindBeatsTheExtension(t *testing.T) {
	// Prefix wins: the compression and encryption extensions say nothing about
	// what the file holds.
	for _, name := range []string{
		"memdump_1_TS.gz", "memdump_1_TS.gz.enc", "memdump_1_TS.bin", "memdump_1_TS",
	} {
		if got := kindFromName(name); got != KindMemoryDump {
			t.Errorf("%s classified as %q", name, got)
		}
	}
	// The sidecar is JSON metadata, not the dump.
	if got := kindFromName("memdump_1_TS.meta.json"); got != KindArtifactBundle {
		t.Errorf("sidecar classified as %q", got)
	}
}

func TestProgressDoesNotCountAgainstTheAttemptCap(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "big.dmp", []byte("a large dump"))
	// Every attempt times out, but each one leaves more on the platform than
	// the last. That is the slow-link case the resume machinery exists for, and
	// it must not be abandoned.
	advanced := int64(0)
	up := &recordingUploader{outcome: func(Upload) (Outcome, error) {
		advanced += 1000
		return Outcome{BytesStored: advanced}, fmt.Errorf("context deadline exceeded")
	}}
	policy := DefaultShipperPolicy()
	policy.MaxAttempts = 3
	s := NewShipper(dir, up, policy, nil)

	for i := 0; i < 10; i++ {
		if _, err := s.ShipOnce(context.Background()); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	if len(up.calls) != 10 {
		t.Fatalf("uploader called %d times; progress was counted as failure and the bundle was abandoned", len(up.calls))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the bundle was removed: %v", err)
	}
}

func TestAnAttemptThatAchievesNothingStillCountsAgainstTheCap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "stuck.dmp", []byte("never moves"))
	// No progress at all: the cap must still stop a tight loop.
	up := &recordingUploader{outcome: func(Upload) (Outcome, error) {
		return Outcome{BytesStored: 0}, fmt.Errorf("connection refused")
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

func TestProgressThenStallStillStopsEventually(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "partial.dmp", []byte("some progress then nothing"))
	calls := 0
	up := &recordingUploader{outcome: func(Upload) (Outcome, error) {
		calls++
		if calls <= 2 {
			return Outcome{BytesStored: int64(calls) * 500}, fmt.Errorf("timeout")
		}
		// Stalls at the same offset from here on.
		return Outcome{BytesStored: 1000}, fmt.Errorf("timeout")
	}}
	policy := DefaultShipperPolicy()
	policy.MaxAttempts = 2
	s := NewShipper(dir, up, policy, nil)

	for i := 0; i < 8; i++ {
		if _, err := s.ShipOnce(context.Background()); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	// Two progressing attempts, then two that achieved nothing, then stop.
	if len(up.calls) != 4 {
		t.Fatalf("uploader called %d times, expected 2 progressing plus the cap of 2", len(up.calls))
	}
}
