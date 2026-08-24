//go:build windows

package main

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	idStatus  = 101
	idToken   = 102
	idRefresh = 103
	idEnroll  = 104
	idTest    = 105
	idStart   = 106
	idStop    = 107

	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	wsChild            = 0x40000000
	wsTabstop          = 0x00010000
	wsBorder           = 0x00800000
	wsVScroll          = 0x00200000
	esAutohscroll      = 0x0080
	esMultiline        = 0x0004
	esReadonly         = 0x0800
	bsPushbutton       = 0x00000000

	wmDestroy = 0x0002
	wmCommand = 0x0111
	wmClose   = 0x0010
	wmSetfont = 0x0030
	bnClicked = 0

	colorWindow = 5
	swShow      = 5
	idcArrow    = 32512
)

var (
	modUser32  = windows.NewLazySystemDLL("user32.dll")
	modKernel  = windows.NewLazySystemDLL("kernel32.dll")
	modShell32 = windows.NewLazySystemDLL("shell32.dll")

	procRegisterClassExW  = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW   = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW    = modUser32.NewProc("DefWindowProcW")
	procGetMessageW       = modUser32.NewProc("GetMessageW")
	procTranslateMessage  = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW  = modUser32.NewProc("DispatchMessageW")
	procShowWindow        = modUser32.NewProc("ShowWindow")
	procUpdateWindow      = modUser32.NewProc("UpdateWindow")
	procPostQuitMessage   = modUser32.NewProc("PostQuitMessage")
	procGetWindowTextW    = modUser32.NewProc("GetWindowTextW")
	procSetWindowTextW    = modUser32.NewProc("SetWindowTextW")
	procGetDlgItem        = modUser32.NewProc("GetDlgItem")
	procLoadCursorW       = modUser32.NewProc("LoadCursorW")
	procGetModuleHandleW = modKernel.NewProc("GetModuleHandleW")
	procShellExecuteW    = modShell32.NewProc("ShellExecuteW")
)

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type msg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

var mainHWND windows.Handle

func runGUI() error {
	runtime.LockOSThread()
	if err := ensureAdminWindows(); err != nil {
		return err
	}

	instance, _, _ := procGetModuleHandleW.Call(0)
	className, _ := windows.UTF16PtrFromString("EDRAgentUI")
	cursor, _, _ := procLoadCursorW.Call(0, uintptr(idcArrow))

	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     windows.Handle(instance),
		HCursor:       windows.Handle(cursor),
		HbrBackground: windows.Handle(colorWindow + 1),
		LpszClassName: className,
	}
	atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return err
	}

	title, _ := windows.UTF16PtrFromString("EDR Agent")
	hwnd, _, err := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		wsOverlappedWindow|wsVisible,
		200, 120, 640, 520,
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return err
	}
	mainHWND = windows.Handle(hwnd)
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	refreshStatus()

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}

func wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case 0x0001: // WM_CREATE
		createControls(hwnd)
		return 0
	case wmCommand:
		if hiword(uint32(wParam)) == bnClicked {
			switch loword(uint32(wParam)) {
			case idRefresh:
				refreshStatus()
			case idEnroll:
				doEnroll(hwnd)
			case idTest:
				out, err := runEdrctl("test-connection")
				setStatus(hwnd, prefixed("Connection test", out, err))
			case idStart:
				out, err := runEdrctl("start")
				setStatus(hwnd, prefixed("Start", out, err))
			case idStop:
				out, err := runEdrctl("stop")
				setStatus(hwnd, prefixed("Stop", out, err))
			}
		}
		return 0
	case wmClose, wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func createControls(hwnd windows.Handle) {
	hInst, _, _ := procGetModuleHandleW.Call(0)
	createChild(hwnd, hInst, "STATIC", "Enrollment token", 16, 12, 200, 18, 0, 0)
	createChild(hwnd, hInst, "EDIT", "", 16, 32, 440, 24, idToken, wsBorder|esAutohscroll|wsTabstop)
	createChild(hwnd, hInst, "BUTTON", "Enroll", 468, 30, 140, 28, idEnroll, bsPushbutton|wsTabstop)
	createChild(hwnd, hInst, "BUTTON", "Refresh", 16, 68, 110, 28, idRefresh, bsPushbutton|wsTabstop)
	createChild(hwnd, hInst, "BUTTON", "Test connection", 136, 68, 140, 28, idTest, bsPushbutton|wsTabstop)
	createChild(hwnd, hInst, "BUTTON", "Start", 286, 68, 90, 28, idStart, bsPushbutton|wsTabstop)
	createChild(hwnd, hInst, "BUTTON", "Stop", 386, 68, 90, 28, idStop, bsPushbutton|wsTabstop)
	createChild(hwnd, hInst, "EDIT", "Loading…", 16, 108, 592, 350, idStatus, wsBorder|esMultiline|esReadonly|wsVScroll)
}

func createChild(parent windows.Handle, inst uintptr, class, title string, x, y, w, h, id int, extra uint32) {
	cls, _ := windows.UTF16PtrFromString(class)
	ttl, _ := windows.UTF16PtrFromString(title)
	style := wsChild | wsVisible | extra
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(cls)),
		uintptr(unsafe.Pointer(ttl)),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent),
		uintptr(id),
		inst,
		0,
	)
}

func refreshStatus() {
	if mainHWND == 0 {
		return
	}
	out, err := runEdrctl("ui")
	setStatus(mainHWND, prefixed("Status", out, err))
}

func doEnroll(hwnd windows.Handle) {
	item, _, _ := procGetDlgItem.Call(uintptr(hwnd), idToken)
	buf := make([]uint16, 1024)
	n, _, _ := procGetWindowTextW.Call(item, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	token := windows.UTF16ToString(buf[:n])
	if token == "" {
		setStatus(hwnd, "Enter an enrollment token, then click Enroll.")
		return
	}
	out, err := runEdrctl("enroll", "--token", token)
	setStatus(hwnd, prefixed("Enroll", out, err))
}

func setStatus(hwnd windows.Handle, text string) {
	item, _, _ := procGetDlgItem.Call(uintptr(hwnd), idStatus)
	p, _ := windows.UTF16PtrFromString(text)
	procSetWindowTextW.Call(item, uintptr(unsafe.Pointer(p)))
}

func prefixed(title, out string, err error) string {
	if err != nil {
		if out == "" {
			return title + " failed: " + err.Error()
		}
		return title + " failed:\r\n" + out
	}
	if out == "" {
		return title + ": ok"
	}
	return title + ":\r\n" + out
}

func loword(v uint32) uint16 { return uint16(v) }
func hiword(v uint32) uint16 { return uint16(v >> 16) }

func ensureAdminWindows() error {
	if exec.Command("net", "session").Run() == nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	ret, _, callErr := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), 0, 0, swShow)
	if ret <= 32 {
		return callErr
	}
	os.Exit(0)
	return nil
}
