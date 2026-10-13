package forensics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// FileRecord is one file on disk as the collector found it.
//
// A path on its own says a file existed. It does not say what was in it, and by
// the time anyone reads the bundle the file is usually gone — deleted by the
// attacker, or with the host. The digest is what turns "a file called
// update.exe was in the temp directory" into something an analyst can look up
// in a threat intelligence service, compare against a known-good build, or
// match against the same file found on another endpoint.
type FileRecord struct {
	Path string `json:"path"`
	// Size is the length at the moment of collection, which is also what the
	// digest covers.
	Size    int64       `json:"size"`
	Mode    string      `json:"mode"`
	ModTime time.Time   `json:"mod_time"`
	Mode32  os.FileMode `json:"-"`
	// SHA256 is empty when the file was not hashed, and Skipped says why.
	// Reported rather than omitted: an analyst needs to know the difference
	// between a file whose contents matched nothing and a file nobody read.
	SHA256 string `json:"sha256,omitempty"`
	// Skipped explains an empty digest: too large, unreadable, or not a
	// regular file.
	Skipped string `json:"skipped,omitempty"`
	// Symlink records where a link pointed, which is evidence in itself.
	Symlink string `json:"symlink,omitempty"`
}

// FileScanLimits bound a scan so collection cannot become the incident.
//
// A collector that hashes every file it finds will, on the wrong host, read a
// hundred gigabytes during an active intrusion — pinning the disk, filling the
// bundle, and taking long enough that the volatile state it was supposed to
// preserve has gone.
type FileScanLimits struct {
	// MaxFiles caps how many entries one directory contributes.
	MaxFiles int
	// MaxHashBytes is the largest file that will be hashed. Larger files are
	// still recorded, with Skipped set.
	MaxHashBytes int64
	// Budget bounds the whole scan. When it is spent, the remaining files are
	// recorded without digests rather than dropped.
	Budget time.Duration
}

// DefaultFileScanLimits keeps a scan to roughly a second of disk work.
func DefaultFileScanLimits() FileScanLimits {
	return FileScanLimits{
		MaxFiles: 200,
		// 32 MiB covers the executables, scripts and archives that matter for
		// attribution. A larger file is named and measured but not read.
		MaxHashBytes: 32 << 20,
		Budget:       5 * time.Second,
	}
}

func (l FileScanLimits) withDefaults() FileScanLimits {
	d := DefaultFileScanLimits()
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxHashBytes <= 0 {
		l.MaxHashBytes = d.MaxHashBytes
	}
	if l.Budget <= 0 {
		l.Budget = d.Budget
	}
	return l
}

// scanDir records the files in one directory, newest first.
//
// Newest first because the files that matter in an intrusion are the ones that
// just appeared, and the cap means something has to be left out. Taking the
// first entries the filesystem happened to return would drop the dropper and
// keep a year-old cache file.
func scanDir(ctx context.Context, dir string, limits FileScanLimits, deadline time.Time) []FileRecord {
	limits = limits.withDefaults()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	type candidate struct {
		rec FileRecord
		mod time.Time
	}
	cands := make([]candidate, 0, len(entries))
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		// Lstat, not Stat: a symlink is recorded as the link it is rather than
		// silently reported as whatever it points at, which on a compromised
		// host may be somewhere else entirely.
		info, lerr := os.Lstat(path)
		if lerr != nil {
			continue
		}
		rec := FileRecord{
			Path:    path,
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			Mode32:  info.Mode(),
			ModTime: info.ModTime().UTC(),
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if target, rerr := os.Readlink(path); rerr == nil {
				rec.Symlink = target
			}
			rec.Skipped = "symbolic link; not followed"
		} else if info.IsDir() {
			rec.Skipped = "directory"
		}
		cands = append(cands, candidate{rec: rec, mod: info.ModTime()})
	}

	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })
	if len(cands) > limits.MaxFiles {
		cands = cands[:limits.MaxFiles]
	}

	out := make([]FileRecord, 0, len(cands))
	for _, c := range cands {
		rec := c.rec
		switch {
		case rec.Skipped != "":
			// Already explained above.
		case ctx.Err() != nil:
			rec.Skipped = "collection deadline passed before this file was read"
		case !deadline.IsZero() && time.Now().After(deadline):
			// The file is still named, sized and timestamped. Dropping it
			// entirely would hide from the reader that it was there at all.
			rec.Skipped = "scan budget spent before this file was read"
		case !rec.Mode32.IsRegular():
			rec.Skipped = "not a regular file"
		case rec.Size > limits.MaxHashBytes:
			rec.Skipped = "larger than the hash limit"
		default:
			digest, herr := hashFileAt(rec.Path, limits.MaxHashBytes)
			if herr != nil {
				rec.Skipped = "unreadable: " + herr.Error()
			} else {
				rec.SHA256 = digest
			}
		}
		out = append(out, rec)
	}
	return out
}

// hashFileAt digests a file, refusing to follow a link and stopping at the
// limit rather than reading a file that grew between the stat and the read.
func hashFileAt(path string, limit int64) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|openNoFollow, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, io.LimitReader(f, limit)); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// statFile records one known path, for the files the collector names directly
// rather than discovers.
func statFile(ctx context.Context, path string, limits FileScanLimits, deadline time.Time) (FileRecord, bool) {
	limits = limits.withDefaults()
	info, err := os.Lstat(path)
	if err != nil {
		return FileRecord{}, false
	}
	rec := FileRecord{
		Path:    path,
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		Mode32:  info.Mode(),
		ModTime: info.ModTime().UTC(),
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		if target, rerr := os.Readlink(path); rerr == nil {
			rec.Symlink = target
		}
		rec.Skipped = "symbolic link; not followed"
	case info.IsDir():
		rec.Skipped = "directory"
	case ctx.Err() != nil:
		rec.Skipped = "collection deadline passed before this file was read"
	case !deadline.IsZero() && time.Now().After(deadline):
		rec.Skipped = "scan budget spent before this file was read"
	case info.Size() > limits.MaxHashBytes:
		rec.Skipped = "larger than the hash limit"
	default:
		digest, herr := hashFileAt(path, limits.MaxHashBytes)
		if herr != nil {
			rec.Skipped = "unreadable: " + herr.Error()
		} else {
			rec.SHA256 = digest
		}
	}
	return rec, true
}

// Paths reduces records to the bare paths the previous bundle format carried.
func Paths(records []FileRecord) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Path)
	}
	return out
}
