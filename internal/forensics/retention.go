package forensics

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"go.uber.org/zap"
)

// RetentionPolicy bounds what the forensics tree is allowed to occupy.
//
// Every detection that collects artifacts, dumps memory or builds a DFIR
// package writes into this tree, and nothing removed anything. On a host that
// detects repeatedly — which is the host you most want an agent running on —
// the tree grows until the disk does not. A security agent that fills the disk
// has caused the incident it was deployed to catch.
//
// Both bounds apply. Age alone cannot stop a single noisy day filling the disk;
// size alone would discard a quiet month's evidence the moment a burst arrives.
type RetentionPolicy struct {
	// MaxAge discards evidence older than this. Zero disables the age bound.
	MaxAge time.Duration
	// MaxBytes caps the whole tree, oldest discarded first. Zero disables it.
	MaxBytes int64
}

// DefaultRetentionPolicy is deliberately conservative on both axes: evidence is
// the reason the agent exists, so the bound is there to prevent an outage, not
// to be tidy.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		MaxAge:   30 * 24 * time.Hour,
		MaxBytes: 2 << 30, // 2 GiB
	}
}

// RetentionResult reports what a sweep removed.
type RetentionResult struct {
	Removed      int
	BytesFreed   int64
	RemainingN   int
	RemainingSum int64
}

type forensicEntry struct {
	path    string
	modTime time.Time
	size    int64
	isDir   bool
}

// Sweep enforces the policy over dir, removing oldest first.
//
// Entries are ranked by modification time rather than by name: a collector that
// writes a timestamped directory and then adds files to it would otherwise be
// judged on the moment it started, not the moment it finished.
func Sweep(dir string, policy RetentionPolicy, logger *zap.Logger) (RetentionResult, error) {
	var res RetentionResult
	if logger == nil {
		logger = zap.NewNop()
	}
	if dir == "" {
		return res, nil
	}
	entries, err := collectEntries(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, err
	}

	// Oldest first, so both bounds discard in the same order and the newest
	// evidence is the last thing to go.
	sort.Slice(entries, func(i, j int) bool { return entries[i].modTime.Before(entries[j].modTime) })

	var total int64
	for _, e := range entries {
		total += e.size
	}

	cutoff := time.Time{}
	if policy.MaxAge > 0 {
		cutoff = time.Now().Add(-policy.MaxAge)
	}

	remove := func(e forensicEntry, reason string) {
		if err := os.RemoveAll(e.path); err != nil {
			logger.Warn("could not remove expired forensic evidence",
				zap.String("path", e.path), zap.Error(err))
			return
		}
		res.Removed++
		res.BytesFreed += e.size
		total -= e.size
		logger.Info("forensic evidence removed by retention policy",
			zap.String("path", e.path),
			zap.String("reason", reason),
			zap.Int64("bytes", e.size),
		)
	}

	kept := entries[:0]
	for _, e := range entries {
		if !cutoff.IsZero() && e.modTime.Before(cutoff) {
			remove(e, "older than the retention window")
			continue
		}
		kept = append(kept, e)
	}

	// Then trim by size, still oldest first.
	if policy.MaxBytes > 0 {
		for _, e := range kept {
			if total <= policy.MaxBytes {
				break
			}
			remove(e, "forensics directory over its size budget")
		}
	}

	// Recount rather than inferring, so the figure reported is what is there.
	remaining, err := collectEntries(dir)
	if err == nil {
		res.RemainingN = len(remaining)
		for _, e := range remaining {
			res.RemainingSum += e.size
		}
	}
	return res, nil
}

// collectEntries lists the top-level items of dir with their sizes. Directories
// are measured whole, because a DFIR package is one piece of evidence however
// many files it contains.
func collectEntries(dir string) ([]forensicEntry, error) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]forensicEntry, 0, len(items))
	for _, item := range items {
		path := filepath.Join(dir, item.Name())
		info, err := item.Info()
		if err != nil {
			continue
		}
		e := forensicEntry{path: path, modTime: info.ModTime(), isDir: item.IsDir()}
		if item.IsDir() {
			e.size, e.modTime = dirSizeAndNewest(path, info.ModTime())
		} else {
			e.size = info.Size()
		}
		out = append(out, e)
	}
	return out, nil
}

// dirSizeAndNewest totals a directory and returns the most recent modification
// inside it.
func dirSizeAndNewest(dir string, fallback time.Time) (int64, time.Time) {
	var total int64
	newest := fallback
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			total += info.Size()
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return total, newest
}

// SweepPeriodically enforces the policy on a timer until ctx ends. It sweeps
// once immediately, so a restart after a burst reclaims space without waiting.
func SweepPeriodically(ctx interface{ Done() <-chan struct{} }, dir string, policy RetentionPolicy, every time.Duration, logger *zap.Logger) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if every <= 0 {
		every = time.Hour
	}
	sweep := func() {
		res, err := Sweep(dir, policy, logger)
		if err != nil {
			logger.Warn("forensics retention sweep failed", zap.String("dir", dir), zap.Error(err))
			return
		}
		if res.Removed > 0 {
			logger.Info("forensics retention sweep complete",
				zap.Int("removed", res.Removed),
				zap.Int64("bytes_freed", res.BytesFreed),
				zap.Int64("bytes_remaining", res.RemainingSum),
			)
		}
	}
	sweep()

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// Validate reports a policy that would delete everything or nothing usefully.
func (p RetentionPolicy) Validate() error {
	if p.MaxAge < 0 {
		return fmt.Errorf("forensics retention: max age cannot be negative")
	}
	if p.MaxBytes < 0 {
		return fmt.Errorf("forensics retention: max size cannot be negative")
	}
	return nil
}
