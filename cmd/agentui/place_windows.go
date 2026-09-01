//go:build windows

package main

import (
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"
	"golang.org/x/sys/windows"
)

var (
	modUser32          = windows.NewLazySystemDLL("user32.dll")
	procSetWindowPos   = modUser32.NewProc("SetWindowPos")
	procGetWindowRect  = modUser32.NewProc("GetWindowRect")
	procGetCursorPos   = modUser32.NewProc("GetCursorPos")
	procSysParamsInfoW = modUser32.NewProc("SystemParametersInfoW")
	procShowWindow     = modUser32.NewProc("ShowWindow")
	procSetForeground  = modUser32.NewProc("SetForegroundWindow")
)

const (
	swpNoSize     = 0x0001
	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010
	spiWorkArea   = 0x0030
)

type winRECT struct {
	Left, Top, Right, Bottom int32
}

type winPOINT struct {
	X, Y int32
}

func registerAppActivate() {}

func stayInMenuBar() {}

func nativeHWND(win fyne.Window) uintptr {
	var hwnd uintptr
	nw, ok := win.(driver.NativeWindow)
	if !ok {
		return 0
	}
	nw.RunNative(func(ctx any) {
		wc, ok := ctx.(driver.WindowsWindowContext)
		if ok {
			hwnd = wc.HWND
		}
	})
	return hwnd
}

func workArea() (x, y, w, h int) {
	var r winRECT
	procSysParamsInfoW.Call(spiWorkArea, 0, uintptr(unsafe.Pointer(&r)), 0)
	return int(r.Left), int(r.Top), int(r.Right - r.Left), int(r.Bottom - r.Top)
}

func placeNearTray(win fyne.Window, width, height float32, nearCursor, _ bool) {
	hwnd := nativeHWND(win)
	if hwnd == 0 {
		return
	}
	scale := float32(1)
	if win.Canvas() != nil {
		scale = win.Canvas().Scale()
	}
	ww := int(width * scale)
	hh := int(height * scale)
	vaX, vaY, vaW, vaH := workArea()
	var x, y int
	if nearCursor {
		var p winPOINT
		procGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
		x, y = cursorAnchor(int(p.X), int(p.Y), ww, hh, vaX, vaY, vaW, vaH, 8, false)
	} else {
		x, y = trayCorner(vaX, vaY, vaW, vaH, ww, hh, 8, false)
	}
	const flags = swpNoSize | swpNoZOrder
	procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), 0, 0, flags)
}

func nativeWorkLogical(win fyne.Window) (float32, float32) {
	_, _, ww, hh := workArea()
	if ww <= 0 || hh <= 0 {
		return 0, 0
	}
	scale := float32(1)
	if win != nil && win.Canvas() != nil && win.Canvas().Scale() > 0.1 {
		scale = win.Canvas().Scale()
	}
	return float32(ww) / scale, float32(hh) / scale
}

func nativeResizeKeepTop(win fyne.Window, width, height float32) bool {
	hwnd := nativeHWND(win)
	if hwnd == 0 {
		return false
	}
	scale := float32(1)
	if win.Canvas() != nil {
		scale = win.Canvas().Scale()
	}
	ww := int(width * scale)
	hh := int(height * scale)
	vaX, vaY, vaW, vaH := workArea()
	if vaH > 48 && hh > vaH-24 {
		hh = vaH - 24
	}
	var r winRECT
	procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	x, y := int(r.Left), int(r.Top)
	if y+hh > vaY+vaH {
		y = vaY + vaH - hh
	}
	if y < vaY {
		y = vaY
	}
	if x < vaX {
		x = vaX
	}
	if x+ww > vaX+vaW && vaW > ww {
		x = vaX + vaW - ww
	}
	procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(ww), uintptr(hh), swpNoZOrder|swpNoActivate)
	_ = vaW
	return true
}

func startNativeWindowDrag(fyne.Window) bool { return false }

func moveNativeWindow(win fyne.Window, dx, dy float32) {
	hwnd := nativeHWND(win)
	if hwnd == 0 {
		return
	}
	scale := float32(1)
	if win.Canvas() != nil {
		scale = win.Canvas().Scale()
	}
	var r winRECT
	procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	x := int(r.Left) + int(dx*scale)
	y := int(r.Top) + int(dy*scale)
	procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), 0, 0, swpNoSize|swpNoZOrder|swpNoActivate)
}

func bringNativeWindow(win fyne.Window) {
	hwnd := nativeHWND(win)
	if hwnd == 0 {
		return
	}
	const swRestore = 9
	procShowWindow.Call(hwnd, swRestore)
	procSetForeground.Call(hwnd)
}
