//go:build linux

package collector

import (
	"encoding/binary"
	"errors"
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

func TestOpenPathByHandleFallsBackToNameToHandleAt(t *testing.T) {
	f := NewFanotifySource("e", "h", nil, nil, nil)
	fsid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	key := fsidKey(fsid)
	f.mountFID.put(key, 9, "/mnt/test")

	oldOpen := openByHandleAtFn
	oldName := nameToHandleAtFn
	oldReadlink := readlinkFn
	defer func() {
		openByHandleAtFn = oldOpen
		nameToHandleAtFn = oldName
		readlinkFn = oldReadlink
	}()

	openByHandleAtFn = func(_ int, _ unix.FileHandle, _ int) (int, error) {
		return -1, unix.EINVAL
	}
	nameCalled := false
	nameToHandleAtFn = func(_ int, path string, _ int) (unix.FileHandle, int, error) {
		nameCalled = true
		if path != "/mnt/test" {
			t.Fatalf("unexpected path: %s", path)
		}
		return unix.NewFileHandle(1, []byte{1}), 1, nil
	}
	readlinkFn = func(_ string) (string, error) {
		return "", errors.New("should not use readlink fallback")
	}

	got, err := f.openPathByHandle(fsid, unix.NewFileHandle(1, []byte{1}))
	if err != nil {
		t.Fatalf("openPathByHandle error: %v", err)
	}
	if !nameCalled {
		t.Fatal("expected NameToHandleAt fallback path to be called")
	}
	if got != "/mnt/test" {
		t.Fatalf("path=%q want /mnt/test", got)
	}
	if n := f.fidResolveByName.Load(); n != 1 {
		t.Fatalf("fidResolveByName=%d want 1", n)
	}
}
