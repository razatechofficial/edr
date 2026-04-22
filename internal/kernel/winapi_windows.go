//go:build windows

package kernel

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	EvtRenderEventXML         = 1
	EvtQueryChannelPath       = 0x1
	EvtQueryReverseDirection  = 0x200
	EvtSubscribeToFutureEvents = 1
)

var (
	wevtapiProc               = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery              = wevtapiProc.NewProc("EvtQuery")
	procEvtNext               = wevtapiProc.NewProc("EvtNext")
	procEvtRender             = wevtapiProc.NewProc("EvtRender")
	procEvtClose              = wevtapiProc.NewProc("EvtClose")
	procEvtCreateBookmark     = wevtapiProc.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark     = wevtapiProc.NewProc("EvtUpdateBookmark")
	procEvtSaveBookmark       = wevtapiProc.NewProc("EvtSaveBookmark")
	procEvtLoadBookmark       = wevtapiProc.NewProc("EvtLoadBookmark")
	procEvtSubscribe          = wevtapiProc.NewProc("EvtSubscribe")
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

func EvtSaveBookmark(bookmark windows.Handle, filePath *uint16) error {
	r0, _, e1 := procEvtSaveBookmark.Call(uintptr(bookmark), uintptr(unsafe.Pointer(filePath)))
	if r0 == 0 {
		if e1 == windows.ERROR_SUCCESS {
			return syscall.EINVAL
		}
		return error(e1)
	}
	return nil
}

func EvtLoadBookmark(filePath *uint16) (windows.Handle, error) {
	r0, _, e1 := procEvtLoadBookmark.Call(uintptr(unsafe.Pointer(filePath)))
	if r0 == 0 {
		if e1 == windows.ERROR_SUCCESS {
			return 0, syscall.EINVAL
		}
		return 0, error(e1)
	}
	return windows.Handle(r0), nil
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
