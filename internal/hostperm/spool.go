package hostperm

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/razatechofficial/edr/internal/platform"
	"github.com/razatechofficial/edr/internal/telemetryqueue"
)

// MinFreeForSpool is the floor operators must keep available so a 2–4 GiB
// offline cache can fill during an ingest outage (Elastic / osquery / Falcon
// disk-queue pattern). Headroom above the cap avoids ENOSPC during rotation.
const MinFreeForSpool = telemetryqueue.MinFreeBytes

func evaluateSpool(it Item) Item {
	data := platform.DataDir()
	dir := filepath.Join(data, "telemetry-queue")
	probe := dir
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		if _, perr := os.Stat(data); perr != nil {
			return fail(it, "Agent data directory is missing. Reinstall as administrator.")
		}
		probe = data
		if err := os.MkdirAll(dir, 0o700); err != nil {
			// Unprivileged UI cannot always create the queue; writable parent is enough.
			free, ferr := diskFree(probe)
			if ferr == nil && free < MinFreeForSpool {
				return fail(it, fmt.Sprintf("Only %.1f GiB free; offline spool needs at least 2 GiB.", float64(free)/float64(1<<30)))
			}
			return ok(it, "Data directory is present. The sensor creates the offline queue on start.")
		}
	}
	free, err := diskFree(probe)
	if err != nil {
		return ok(it, "Offline event spool path is present.")
	}
	if free < MinFreeForSpool {
		return fail(it, fmt.Sprintf("Only %.1f GiB free; spool needs 2–4 GiB reserved for an ingest outage.", float64(free)/float64(1<<30)))
	}
	return ok(it, fmt.Sprintf("Writable · %.1f GiB free · cap 3 GiB · retain 7 days", float64(free)/float64(1<<30)))
}

// DiskFree returns available bytes on the volume containing path.
func DiskFree(path string) (uint64, error) {
	return diskFree(path)
}
