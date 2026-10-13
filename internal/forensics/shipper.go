package forensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Upload is one bundle handed to the platform.
type Upload struct {
	Path        string
	UID         string
	AlertUID    string
	RuleUID     string
	Kind        string
	ContentType string
	CollectedAt time.Time
}

// Outcome is what the platform reported about an upload.
type Outcome struct {
	// Stored means the platform holds the bundle and verified its digest. Only
	// then is the local copy redundant.
	Stored      bool
	BytesStored int64
	StorageRef  string
	Message     string
}

// Uploader ships a bundle. Implemented by the platform client; an interface
// here so this package does not depend on the transport, and so the shipping
// policy can be tested without a server.
type Uploader interface {
	Upload(ctx context.Context, up Upload) (Outcome, error)
}

// ErrUnsupported is returned by an Uploader whose platform has no upload API.
// The shipper stops after seeing it rather than retrying every cycle.
var ErrUnsupported = errors.New("forensics: the platform does not accept uploads")

// ErrOverBudget is returned when the platform has refused the bundle because
// this tenant's evidence allowance is spent.
//
// Held back rather than retried and rather than given up on. The allowance
// refills, so the evidence will be accepted later; retrying on the normal cycle
// would spend the endpoint's bandwidth being refused every few minutes, and
// counting it against the attempt cap would abandon evidence over a condition
// that has nothing to do with the bundle.
var ErrOverBudget = errors.New("forensics: the platform's evidence allowance is spent")

// shippedSuffix marks a bundle the platform has confirmed.
//
// A marker file beside the bundle rather than a database: the agent may be
// killed at any moment, including by the attacker it is watching, and a marker
// that is created by rename is either there or not. The bundle itself is left
// in place for local triage and removed by the retention sweep on its own
// schedule — the upload makes the evidence safe, it does not make it unwanted.
const shippedSuffix = ".shipped"

// ShipperPolicy bounds how hard the agent tries.
type ShipperPolicy struct {
	// Interval is how often the directory is scanned.
	Interval time.Duration
	// PerBundleTimeout bounds one upload. A dump on a slow link must not hold
	// the loop open indefinitely while newer evidence waits behind it.
	PerBundleTimeout time.Duration
	// MaxAttempts is how many times one bundle is retried across cycles before
	// it is left alone. Without a cap, a bundle the platform will always refuse
	// is retried for the life of the host.
	MaxAttempts int
	// BudgetBackoff is how long to stop offering evidence after the platform
	// says the allowance is spent. The allowance is daily, so this only has to
	// be long enough to stop a tight loop.
	BudgetBackoff time.Duration
}

// DefaultShipperPolicy ships promptly without making the upload itself a
// noticeable load on the endpoint.
func DefaultShipperPolicy() ShipperPolicy {
	return ShipperPolicy{
		Interval:         2 * time.Minute,
		PerBundleTimeout: 10 * time.Minute,
		MaxAttempts:      8,
		BudgetBackoff:    time.Hour,
	}
}

// Shipper moves collected evidence off the endpoint.
//
// Evidence that only ever lives on the host under investigation is evidence the
// attacker can reach, and it is lost when the machine is reimaged — which is
// usually the first thing that happens after a confirmed detection.
type Shipper struct {
	dir      string
	uploader Uploader
	policy   ShipperPolicy
	logger   *zap.Logger

	// attempts counts failures per bundle for this process. Deliberately not
	// persisted: a restart is a reasonable moment to try again, and the cap
	// exists to stop a tight loop, not to give up permanently.
	attempts map[string]int
	// unsupported latches once the platform says it has no upload API.
	unsupported bool
	// holdUntil pauses shipping after the platform refuses on allowance
	// grounds. Not persisted: a restart retrying once is harmless, and
	// persisting it would hold evidence back across a restart that may have
	// been days later.
	holdUntil time.Time
	// now is overridable so the hold can be tested without sleeping.
	now func() time.Time
}

// NewShipper returns a shipper over dir. A nil uploader disables it, which is
// the state of an agent enrolled with a platform that has no forensics API.
func NewShipper(dir string, uploader Uploader, policy ShipperPolicy, logger *zap.Logger) *Shipper {
	if logger == nil {
		logger = zap.NewNop()
	}
	if policy.Interval <= 0 {
		policy.Interval = DefaultShipperPolicy().Interval
	}
	if policy.PerBundleTimeout <= 0 {
		policy.PerBundleTimeout = DefaultShipperPolicy().PerBundleTimeout
	}
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = DefaultShipperPolicy().MaxAttempts
	}
	if policy.BudgetBackoff <= 0 {
		policy.BudgetBackoff = DefaultShipperPolicy().BudgetBackoff
	}
	return &Shipper{
		dir:      strings.TrimSpace(dir),
		uploader: uploader,
		policy:   policy,
		logger:   logger,
		attempts: map[string]int{},
		now:      time.Now,
	}
}

// Enabled reports whether this shipper can do anything.
func (s *Shipper) Enabled() bool {
	return s != nil && s.dir != "" && s.uploader != nil && !s.unsupported
}

// ShipOnce scans the directory and uploads what has not been confirmed. It
// returns the number of bundles the platform accepted.
func (s *Shipper) ShipOnce(ctx context.Context) (int, error) {
	if !s.Enabled() {
		return 0, nil
	}
	if held := s.heldUntil(); !held.IsZero() {
		// Nothing is attempted while the allowance is known to be spent. The
		// bundles stay on disk and the next cycle after the hold tries again.
		s.logger.Debug("evidence shipping held until the platform allowance refills",
			zap.Time("until", held))
		return 0, nil
	}
	pending, err := s.pending()
	if err != nil {
		return 0, err
	}
	shipped := 0
	for _, up := range pending {
		if ctx.Err() != nil {
			return shipped, ctx.Err()
		}
		if s.attempts[up.UID] >= s.policy.MaxAttempts {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, s.policy.PerBundleTimeout)
		out, err := s.uploader.Upload(attemptCtx, up)
		cancel()
		if errors.Is(err, ErrUnsupported) {
			// Said once, logged once. The agent keeps collecting and keeps its
			// bundles locally, which is the behaviour before any upload path
			// existed.
			s.unsupported = true
			s.logger.Info("platform does not accept forensic uploads; evidence stays on the endpoint")
			return shipped, nil
		}
		if errors.Is(err, ErrOverBudget) {
			// Not counted against the attempt cap: the bundle is fine and will
			// be accepted once the allowance refills. Counting it would
			// abandon evidence for a reason that is not about the evidence.
			s.holdUntil = s.clock().Add(s.policy.BudgetBackoff)
			s.logger.Warn("platform evidence allowance is spent; holding evidence locally",
				zap.String("bundle_uid", up.UID),
				zap.Duration("retry_in", s.policy.BudgetBackoff),
				zap.Error(err),
			)
			return shipped, nil
		}
		if err != nil {
			s.attempts[up.UID]++
			s.logger.Warn("forensic bundle could not be shipped",
				zap.String("bundle_uid", up.UID),
				zap.String("path", up.Path),
				zap.Int("attempts", s.attempts[up.UID]),
				zap.Error(err),
			)
			continue
		}
		if !out.Stored {
			// The platform answered but did not take it — a digest mismatch, or
			// an incomplete transfer. The local copy stays, because it may be
			// the only intact one.
			s.attempts[up.UID]++
			s.logger.Warn("platform did not accept a forensic bundle",
				zap.String("bundle_uid", up.UID),
				zap.String("message", out.Message),
				zap.Int64("bytes_stored", out.BytesStored),
			)
			continue
		}
		if err := s.markShipped(up, out); err != nil {
			// Not fatal, and not counted as a failure: the bundle is safely
			// stored. The cost is that it will be offered again, and the
			// platform will recognise it and answer "already stored".
			s.logger.Warn("forensic bundle shipped but could not be marked",
				zap.String("bundle_uid", up.UID), zap.Error(err))
		}
		delete(s.attempts, up.UID)
		shipped++
		s.logger.Info("forensic bundle shipped",
			zap.String("bundle_uid", up.UID),
			zap.String("alert_uid", up.AlertUID),
			zap.Int64("bytes", out.BytesStored),
			zap.String("storage_ref", out.StorageRef),
		)
	}
	return shipped, nil
}

// heldUntil reports the time shipping is paused until, or the zero time when
// it is not paused.
func (s *Shipper) heldUntil() time.Time {
	if s.holdUntil.IsZero() {
		return time.Time{}
	}
	if s.clock().Before(s.holdUntil) {
		return s.holdUntil
	}
	s.holdUntil = time.Time{}
	return time.Time{}
}

func (s *Shipper) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// Run ships on a timer until ctx ends, starting immediately so evidence
// collected just before a restart is not left waiting for a full interval.
func (s *Shipper) Run(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	once := func() {
		if _, err := s.ShipOnce(ctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("forensic shipping cycle failed", zap.Error(err))
		}
	}
	once()
	ticker := time.NewTicker(s.policy.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.Enabled() {
				return
			}
			once()
		}
	}
}

// pending lists bundles that have not been confirmed, oldest first so evidence
// is shipped in the order it was collected.
func (s *Shipper) pending() ([]Upload, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type candidate struct {
		up      Upload
		modTime time.Time
	}
	var out []candidate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// .tmp is a write in progress and .shipped is a marker; neither is
		// evidence. Uploading a .tmp would send a half-written bundle whose
		// digest describes nothing.
		if strings.HasSuffix(name, shippedSuffix) || strings.HasSuffix(name, ".tmp") {
			continue
		}
		path := filepath.Join(s.dir, name)
		if _, err := os.Lstat(path + shippedSuffix); err == nil {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		out = append(out, candidate{up: s.describe(path, name, info.ModTime()), modTime: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].modTime.Before(out[j].modTime) })
	ups := make([]Upload, 0, len(out))
	for _, c := range out {
		ups = append(ups, c.up)
	}
	return ups, nil
}

// describe works out what a file on disk is.
//
// A bundle written by WriteBundle carries its own metadata, which is read back
// rather than re-derived from the filename: the filename is a convenience, and
// one that is truncated and sanitised. When the file cannot be read as a
// bundle — a memory dump, an archive — the filename is all there is.
func (s *Shipper) describe(path, name string, modTime time.Time) Upload {
	up := Upload{
		Path:        path,
		UID:         uploadUID(name),
		Kind:        kindFromName(name),
		ContentType: contentTypeFromName(name),
		CollectedAt: modTime.UTC(),
	}
	if up.Kind == string(KindArtifactBundle) {
		if meta, ok := readBundleMeta(path); ok {
			up.AlertUID = safeName(meta.Alert.AlertID, "")
			up.RuleUID = safeName(meta.Alert.RuleID, "")
			if !meta.Collected.IsZero() {
				up.CollectedAt = meta.Collected.UTC()
			}
		}
	}
	return up
}

// Kind values match the platform's closed set.
type kind = string

const (
	// KindArtifactBundle is the JSON bundle WriteBundle produces.
	KindArtifactBundle kind = "artifact_bundle"
	// KindMemoryDump is a process or system memory image.
	KindMemoryDump kind = "memory_dump"
	// KindDFIRPackage is a packaged collection for an external DFIR tool.
	KindDFIRPackage kind = "dfir_package"
)

func kindFromName(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return KindArtifactBundle
	case strings.HasSuffix(lower, ".dmp"), strings.HasSuffix(lower, ".raw"),
		strings.HasSuffix(lower, ".mem"), strings.HasSuffix(lower, ".core"):
		return KindMemoryDump
	default:
		return KindDFIRPackage
	}
}

func contentTypeFromName(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return "application/json"
	case strings.HasSuffix(lower, ".gz"), strings.HasSuffix(lower, ".tgz"):
		return "application/gzip"
	case strings.HasSuffix(lower, ".zip"):
		return "application/zip"
	default:
		return "application/octet-stream"
	}
}

// uploadUID derives a stable identifier from the filename.
//
// Stability is the whole requirement: the same file must produce the same
// identifier on every attempt, or a resumed upload becomes a second copy in the
// platform's storage. The filename already encodes the collection timestamp and
// the alert, and it does not change once written.
func uploadUID(name string) string {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	return safeName(base, "bundle")
}

// bundleMeta is the part of StoredBundle the shipper needs. Decoded into its
// own type so a change to the bundle format cannot break shipping.
type bundleMeta struct {
	Alert struct {
		AlertID string `json:"alert_id"`
		RuleID  string `json:"rule_id"`
	} `json:"alert"`
	Collected time.Time `json:"collected_at"`
}

// readBundleMeta reads the header of a JSON bundle.
//
// Bounded: a bundle is written by this agent, but a file in this directory is
// not necessarily one, and decoding an arbitrary multi-gigabyte file to find an
// alert identifier would be a denial of service against the agent itself.
func readBundleMeta(path string) (bundleMeta, bool) {
	f, err := os.Open(path)
	if err != nil {
		return bundleMeta{}, false
	}
	defer func() { _ = f.Close() }()
	var meta bundleMeta
	dec := json.NewDecoder(newBoundedReader(f, 1<<20))
	if err := dec.Decode(&meta); err != nil {
		return bundleMeta{}, false
	}
	return meta, true
}

// markShipped records the platform's confirmation beside the bundle.
func (s *Shipper) markShipped(up Upload, out Outcome) error {
	record := map[string]any{
		"bundle_uid":   up.UID,
		"storage_ref":  out.StorageRef,
		"bytes_stored": out.BytesStored,
		"shipped_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	marker := up.Path + shippedSuffix
	tmp := marker + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write shipped marker: %w", err)
	}
	if err := os.Rename(tmp, marker); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit shipped marker: %w", err)
	}
	return nil
}
