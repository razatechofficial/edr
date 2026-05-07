//go:build linux

package collector

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestResolveFanotifyFIDPathGracefulWithZeroHandle(t *testing.T) {
	t.Parallel()
	f := NewFanotifySource("e", "h", nil, nil, nil)
	f.fanReportFIDEnabled = true
	// One event: metadata + minimal FID info (invalid handle)
	ev := make([]byte, 64)
	binary.LittleEndian.PutUint32(ev[0:4], uint32(len(ev))) // event_len
	binary.LittleEndian.PutUint16(ev[10:12], 24)            // metadata_len
	binary.LittleEndian.PutUint64(ev[8:16], uint64(unix.FAN_OPEN))
	binary.LittleEndian.PutUint32(ev[16:20], 0xffffffff) // FAN_NOFD
	binary.LittleEndian.PutUint32(ev[20:24], 1)
	// Info at offset 24: type FID, len 20, fsid 8, file_handle header 8 + 0 payload
	off := 24
	ev[off] = fanEventInfoTypeFID
	binary.LittleEndian.PutUint16(ev[off+2:off+4], 20)
	copy(ev[off+4:off+12], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.LittleEndian.PutUint32(ev[off+12:off+16], 0) // handle_bytes = 0
	binary.LittleEndian.PutUint32(ev[off+16:off+20], 0) // handle_type

	if p := f.resolveFanotifyFIDPath(ev); p != "" {
		t.Fatalf("expected empty path, got %q", p)
	}
}

func TestUnescapeMountinfoPath(t *testing.T) {
	t.Parallel()
	if got := unescapeMountinfoPath(`foo\040bar`); got != "foo bar" {
		t.Fatal(got)
	}
}
