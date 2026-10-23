//go:build windows

package kernel

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	EvtRenderEventXML          = 1
	EvtQueryChannelPath        = 0x1
	EvtQueryReverseDirection   = 0x200
	EvtSubscribeToFutureEvents = 1
)

var (
	wevtapiProc           = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery          = wevtapiProc.NewProc("EvtQuery")
	procEvtNext           = wevtapiProc.NewProc("EvtNext")
	procEvtRender         = wevtapiProc.NewProc("EvtRender")
	procEvtClose          = wevtapiProc.NewProc("EvtClose")
	procEvtCreateBookmark = wevtapiProc.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = wevtapiProc.NewProc("EvtUpdateBookmark")
	procEvtSubscribe      = wevtapiProc.NewProc("EvtSubscribe")
)

func EvtQuery(session, path, query *uint16, flags uint32) (windows.Handle, error) {
	r0, _, e1 := procEvtQuery.Call(
		uintptr(unsafe.Pointer(session)),
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(query)),
		uintptr(flags),
	)
	if r0 == 0 {
		if e1 == windows.ERROR_SUCCESS {
			return 0, syscall.EINVAL
		}
		return 0, error(e1)
	}
	return windows.Handle(r0), nil
}

func EvtNext(resultSet windows.Handle, events []windows.Handle, timeoutMS uint32, flags uint32) (uint32, error) {
	var returned uint32
	r0, _, e1 := procEvtNext.Call(
		uintptr(resultSet),
		uintptr(len(events)),
		uintptr(unsafe.Pointer(&events[0])),
		uintptr(timeoutMS),
		uintptr(flags),
		uintptr(unsafe.Pointer(&returned)),
	)
	if r0 == 0 {
		if errno, ok := e1.(windows.Errno); ok && errno == windows.ERROR_NO_MORE_ITEMS {
			return 0, windows.ERROR_NO_MORE_ITEMS
		}
		if e1 == windows.ERROR_SUCCESS {
			return 0, syscall.EINVAL
		}
		return 0, error(e1)
	}
	return returned, nil
}

func EvtRender(context, fragment windows.Handle, flags uint32, buf []uint16) (used uint32, propertyCount uint32, err error) {
	r0, _, e1 := procEvtRender.Call(
		uintptr(context),
		uintptr(fragment),
		uintptr(flags),
		uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if r0 == 0 {
		return used, propertyCount, error(e1)
	}
	return used, propertyCount, nil
}

func EvtClose(h windows.Handle) {
	if h == 0 {
		return
	}
	_, _, _ = procEvtClose.Call(uintptr(h))
}

func EvtCreateBookmark(bookmarkXML *uint16) (windows.Handle, error) {
	r0, _, e1 := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(bookmarkXML)))
	if r0 == 0 {
		if e1 == windows.ERROR_SUCCESS {
			return 0, syscall.EINVAL
		}
		return 0, error(e1)
	}
	return windows.Handle(r0), nil
}

func EvtUpdateBookmark(bookmark, event windows.Handle) error {
	r0, _, e1 := procEvtUpdateBookmark.Call(uintptr(bookmark), uintptr(event))
	if r0 == 0 {
		if e1 == windows.ERROR_SUCCESS {
			return syscall.EINVAL
		}
		return error(e1)
	}
	return nil
}

// EvtRenderBookmark serialises a bookmark handle to its XML form.
// https://learn.microsoft.com/windows/win32/api/winevt/ne-winevt-evt_render_flags
const EvtRenderBookmark = 2

// EvtSaveBookmark persists a bookmark to filePath.
//
// There is no EvtSaveBookmark export in wevtapi.dll — the Windows Event Log API
// has no save call at all. A bookmark is persisted by rendering it to XML with
// EvtRender(EvtRenderBookmark) and writing that text; it is restored by passing
// the same text to EvtCreateBookmark. This package previously declared
// EvtSaveBookmark and EvtLoadBookmark as exports, so the first call to either
// panicked in LazyProc.mustFind with "The specified procedure could not be
// found", taking down the EVTX collectors that checkpoint with them.
//
// The signature is kept so callers keep their own temp-file and atomic-rename
// handling.
func EvtSaveBookmark(bookmark windows.Handle, filePath *uint16) error {
	if bookmark == 0 {
		return syscall.EINVAL
	}
	// Bookmark XML for a handful of channels is small; this sizes the common
	// case in one call and grows only when the API says it must.
	buf := make([]uint16, 2048)
	used, _, err := EvtRender(0, bookmark, EvtRenderBookmark, buf)
	if err != nil {
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return err
		}
		// used is the required size in bytes, so round up to whole uint16s.
		buf = make([]uint16, int(used)/2+2)
		if used, _, err = EvtRender(0, bookmark, EvtRenderBookmark, buf); err != nil {
			return err
		}
	}
	n := int(used) / 2
	if n > len(buf) {
		n = len(buf)
	}
	path := windows.UTF16PtrToString(filePath)
	if path == "" {
		return syscall.EINVAL
	}
	// 0600: a bookmark records which security events this host has already
	// shipped, so it is operational state, not world-readable information.
	return os.WriteFile(path, []byte(windows.UTF16ToString(buf[:n])), 0o600)
}

// EvtLoadBookmark restores a bookmark previously written by EvtSaveBookmark.
func EvtLoadBookmark(filePath *uint16) (windows.Handle, error) {
	path := windows.UTF16PtrToString(filePath)
	if path == "" {
		return 0, syscall.EINVAL
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	xml, err := windows.UTF16PtrFromString(string(data))
	if err != nil {
		return 0, err
	}
	return EvtCreateBookmark(xml)
}

func EvtSubscribe(session, signalEvent windows.Handle, channel, query *uint16, bookmark windows.Handle, context uintptr, callback uintptr, flags uint32) (windows.Handle, error) {
	r0, _, e1 := procEvtSubscribe.Call(
		uintptr(session),
		uintptr(signalEvent),
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(query)),
		uintptr(bookmark),
		context,
		callback,
		uintptr(flags),
	)
	if r0 == 0 {
		if e1 == windows.ERROR_SUCCESS {
			return 0, syscall.EINVAL
		}
		return 0, error(e1)
	}
	return windows.Handle(r0), nil
}
