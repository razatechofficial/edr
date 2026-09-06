//go:build windows

// Command edr-console is a CGO-free Win32 operator window.
// Fyne/GLFW needs OpenGL and exits immediately on many Server/RDP sessions.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/razatechofficial/edr/internal/platform"
	"golang.org/x/sys/windows"
)

const (
	wsVisible      = 0x10000000
	wsChild        = 0x40000000
	wsTabstop      = 0x00010000
	wsBorder       = 0x00800000
	wsVscroll      = 0x00200000
	esMultiline    = 0x0004
	esAutovscroll  = 0x0040
	esReadonly     = 0x0800
	esAutohscroll  = 0x0080
	bsDefault      = 0x0001
	idStatus       = 1001
	idToken        = 1002
	idEnroll       = 1003
	idStart        = 1004
	idRepair       = 1005
	idRecheck      = 1006
	idTitle        = 1101
	idSubtitle     = 1102
	idTokenLabel   = 1103
	idHint         = 1104
	wmCommand      = 0x0111
	wmDestroy      = 0x0002
	wmSetFont      = 0x0030
	wmSetText      = 0x000C
	wmGetText      = 0x000D
	wmGetTextLen   = 0x000E
	wmAppStatus    = 0x8001
	colorWindow    = 5
	swShow         = 5
	scManagerConn  = 0x0001
	scManagerEnum  = 0x0004
	serviceQuerySt = 0x0004
	serviceQueryCf = 0x0001
	waitTimeout    = 0x00000102
)

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	comctl32             = windows.NewLazySystemDLL("comctl32.dll")
	advapi32             = windows.NewLazySystemDLL("advapi32.dll")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procSetWindowTextW   = user32.NewProc("SetWindowTextW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetSysColorBrush = user32.NewProc("GetSysColorBrush")
	procSetFocus         = user32.NewProc("SetFocus")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procCreateFontW      = gdi32.NewProc("CreateFontW")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procShellExecuteExW  = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
	procOpenSCManagerW   = advapi32.NewProc("OpenSCManagerW")
	procOpenServiceW     = advapi32.NewProc("OpenServiceW")
	procQueryServiceSt   = advapi32.NewProc("QueryServiceStatus")
	procCloseServiceH    = advapi32.NewProc("CloseServiceHandle")

	hwndMain    windows.Handle
	hwndStatus  windows.Handle
	hwndToken   windows.Handle
	hwndEnroll  windows.Handle
	hwndStart   windows.Handle
	hwndRepair  windows.Handle
	hwndRecheck windows.Handle
	fontUI      windows.Handle
	fontTitle   windows.Handle
	busy        atomic.Bool
	statusText  atomic.Value
)

type shellExecuteInfo struct {
	CbSize       uint32
	FMask        uint32
	Hwnd         windows.Handle
	LpVerb       *uint16
	LpFile       *uint16
	LpParameters *uint16
	LpDirectory  *uint16
	NShow        int32
	HInstApp     windows.Handle
	LpIDList     uintptr
	LpClass      *uint16
	HKeyClass    windows.Handle
	DwHotKey     uint32
	HIcon        windows.Handle
	HProcess     windows.Handle
}

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

type serviceStatus struct {
	Type             uint32
	State            uint32
	ControlsAccepted uint32
	Win32ExitCode    uint32
	ServiceSpecific  uint32
	CheckPoint       uint32
	WaitHint         uint32
}

func main() {
	logf("winconsole start args=%v", os.Args)
	if err := runWindow(); err != nil {
		logf("fatal: %v", err)
		alert("EDR Agent", err.Error())
		os.Exit(1)
	}
}

func runWindow() error {
	initCommonControls()
	class, _ := windows.UTF16PtrFromString("EdrWinConsole")
	title, _ := windows.UTF16PtrFromString("EDR Agent")
	hmod, _, _ := procGetModuleHandleW.Call(0)
	inst := windows.Handle(hmod)
	bg, _, _ := procGetSysColorBrush.Call(colorWindow)
	wc := wndClassEx{
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     inst,
		HbrBackground: windows.Handle(bg),
		LpszClassName: class,
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		var last uint32
		if e, ok := err.(windows.Errno); ok {
			last = uint32(e)
		}
		if last != 1410 {
			return fmt.Errorf("register window class: %v", err)
		}
	}
	hwnd, _, err := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)),
		0x00CA0000, // WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
		180, 100, 520, 500,
		0, 0, uintptr(inst), 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("create window: %v", err)
	}
	hwndMain = windows.Handle(hwnd)
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	go refreshAsync()
	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return nil
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case 0x0001: // WM_CREATE
		createChildren(hwnd)
		return 0
	case wmAppStatus:
		applyStatus()
		return 0
	case wmCommand:
		if uint16(wParam>>16) != 0 {
			break
		}
		switch uint16(wParam) {
		case idEnroll:
			if !busy.CompareAndSwap(false, true) {
				return 0
			}
			setBusy(true)
			go doEnroll()
		case idStart:
			if !busy.CompareAndSwap(false, true) {
				return 0
			}
			setBusy(true)
			go doStart()
		case idRepair:
			if !busy.CompareAndSwap(false, true) {
				return 0
			}
			setBusy(true)
			go doRepair()
		case idRecheck:
			if !busy.Load() {
				go refreshAsync()
			}
		}
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func createChildren(parent windows.Handle) {
	fontTitle = makeFont(22, 600)
	fontUI = makeFont(16, 400)
	createCtl(parent, "STATIC", "EDR Agent", idTitle, 24, 18, 460, 28, wsVisible|wsChild)
	createCtl(parent, "STATIC", "Enroll this device and start the sensor.", idSubtitle, 24, 48, 460, 20, wsVisible|wsChild)
	hwndStatus = createCtl(parent, "EDIT", "Checking status…", idStatus, 24, 80, 456, 168, wsVisible|wsChild|wsBorder|wsVscroll|esMultiline|esAutovscroll|esReadonly)
	createCtl(parent, "STATIC", "Enrollment token", idTokenLabel, 24, 262, 456, 18, wsVisible|wsChild)
	hwndToken = createCtl(parent, "EDIT", "", idToken, 24, 284, 456, 28, wsVisible|wsChild|wsTabstop|wsBorder|esAutohscroll)
	hwndEnroll = createCtl(parent, "BUTTON", "Enroll", idEnroll, 24, 328, 104, 34, wsVisible|wsChild|wsTabstop|bsDefault)
	hwndStart = createCtl(parent, "BUTTON", "Start sensor", idStart, 136, 328, 112, 34, wsVisible|wsChild|wsTabstop)
	hwndRepair = createCtl(parent, "BUTTON", "Repair", idRepair, 256, 328, 104, 34, wsVisible|wsChild|wsTabstop)
	hwndRecheck = createCtl(parent, "BUTTON", "Refresh", idRecheck, 368, 328, 112, 34, wsVisible|wsChild|wsTabstop)
	createCtl(parent, "STATIC", "Enroll, Start, and Repair may ask for Administrator. This window stays open.", idHint, 24, 376, 456, 36, wsVisible|wsChild)
	applyFonts(parent)
	procSetFocus.Call(uintptr(hwndToken))
}

func createCtl(parent windows.Handle, class, text string, id int, x, y, w, h int, style uint32) windows.Handle {
	cls, _ := windows.UTF16PtrFromString(class)
	txt, _ := windows.UTF16PtrFromString(text)
	ex := uintptr(0)
	if class == "EDIT" {
		ex = 0x200 // WS_EX_CLIENTEDGE
	}
	hwnd, _, _ := procCreateWindowExW.Call(
		ex,
		uintptr(unsafe.Pointer(cls)),
		uintptr(unsafe.Pointer(txt)),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent), uintptr(id), 0, 0,
	)
	return windows.Handle(hwnd)
}

func applyFonts(parent windows.Handle) {
	ids := []windows.Handle{hwndStatus, hwndToken, hwndEnroll, hwndStart, hwndRepair, hwndRecheck}
	for _, h := range ids {
		if h != 0 && fontUI != 0 {
			procSendMessageW.Call(uintptr(h), wmSetFont, uintptr(fontUI), 1)
		}
	}
	if fontTitle != 0 {
		if t := findChild(parent, idTitle); t != 0 {
			procSendMessageW.Call(uintptr(t), wmSetFont, uintptr(fontTitle), 1)
		}
	}
	for _, id := range []int{idSubtitle, idTokenLabel, idHint} {
		if h := findChild(parent, id); h != 0 && fontUI != 0 {
			procSendMessageW.Call(uintptr(h), wmSetFont, uintptr(fontUI), 1)
		}
	}
}

func findChild(parent windows.Handle, id int) windows.Handle {
	p, _, _ := user32.NewProc("GetDlgItem").Call(uintptr(parent), uintptr(id))
	return windows.Handle(p)
}

func makeFont(px, weight int32) windows.Handle {
	face, _ := windows.UTF16PtrFromString("Segoe UI")
	h, _, _ := procCreateFontW.Call(
		uintptr(px), 0, 0, 0, uintptr(weight),
		0, 0, 0, 1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(face)),
	)
	return windows.Handle(h)
}

func initCommonControls() {
	type icc struct{ Size, ICC uint32 }
	v := icc{Size: 8, ICC: 0x0000FFFF}
	comctl32.NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&v)))
}

func setBusy(on bool) {
	busy.Store(on)
	en := uintptr(1)
	if on {
		en = 0
	}
	for _, h := range []windows.Handle{hwndEnroll, hwndStart, hwndRepair} {
		if h != 0 {
			procEnableWindow.Call(uintptr(h), en)
		}
	}
}

func postStatus(s string) {
	statusText.Store(s)
	if hwndMain != 0 {
		procPostMessageW.Call(uintptr(hwndMain), wmAppStatus, 0, 0)
	}
}

func applyStatus() {
	s, _ := statusText.Load().(string)
	if hwndStatus == 0 || s == "" {
		return
	}
	p, _ := windows.UTF16PtrFromString(s)
	procSetWindowTextW.Call(uintptr(hwndStatus), uintptr(unsafe.Pointer(p)))
}

func tokenText() string {
	if hwndToken == 0 {
		return ""
	}
	n, _, _ := procSendMessageW.Call(uintptr(hwndToken), wmGetTextLen, 0, 0)
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	procSendMessageW.Call(uintptr(hwndToken), wmGetText, n+1, uintptr(unsafe.Pointer(&buf[0])))
	return strings.TrimSpace(windows.UTF16ToString(buf))
}

func refreshAsync() {
	postStatus(collectStatus())
}

func collectStatus() string {
	var b strings.Builder
	state, detail := serviceSnapshot()
	b.WriteString("Sensor\r\n  ")
	b.WriteString(state)
	if detail != "" {
		b.WriteString("  ·  " + detail)
	}
	b.WriteString("\r\n\r\nEnrollment\r\n  ")
	enrolled, agentID := enrollmentSnapshot()
	if enrolled {
		b.WriteString("This device is enrolled")
		if agentID != "" {
			b.WriteString("\r\n  Agent ID  " + agentID)
		}
	} else {
		b.WriteString("Not enrolled  ·  paste a token and click Enroll")
	}
	b.WriteString("\r\n")
	return b.String()
}

func serviceSnapshot() (state, detail string) {
	scm, _, err := procOpenSCManagerW.Call(0, 0, scManagerConn|scManagerEnum)
	if scm == 0 {
		if err != nil {
			return "Cannot read service status", "Refresh after install finishes, or click Repair."
		}
		return "Cannot read service status", "Click Repair if the sensor is missing."
	}
	defer procCloseServiceH.Call(scm)
	name, _ := windows.UTF16PtrFromString("EDRAgent")
	svc, _, _ := procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(name)), serviceQuerySt|serviceQueryCf)
	if svc == 0 {
		return "Not installed", "Click Repair to register EDRAgent."
	}
	defer procCloseServiceH.Call(svc)
	var st serviceStatus
	r, _, _ := procQueryServiceSt.Call(svc, uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return "Registered", "Automatic"
	}
	switch st.State {
	case 4:
		return "Running", ""
	case 1:
		return "Stopped", "Click Start sensor."
	case 2:
		return "Starting…", ""
	default:
		return fmt.Sprintf("State %d", st.State), ""
	}
}

func enrollmentSnapshot() (bool, string) {
	p := filepath.Join(platform.DataDir(), "xdr-tls", "enrollment.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return false, ""
	}
	var meta struct {
		AgentID string `json:"agent_id"`
	}
	if json.Unmarshal(raw, &meta) != nil || strings.TrimSpace(meta.AgentID) == "" {
		return false, ""
	}
	return true, meta.AgentID
}

func finishWork() {
	refreshAsync()
	setBusy(false)
}

func doRepair() {
	postStatus("Registering the sensor…\r\nAllow Administrator if Windows asks.")
	if err := runElevated(12000, filepath.Join(platform.InstallDir(), "edr-svcreg.exe")); err != nil {
		postStatus("Could not register the sensor.\r\n\r\n" + err.Error() + "\r\n\r\nAllow Administrator if prompted, then click Repair again.")
		setBusy(false)
		return
	}
	time.Sleep(300 * time.Millisecond)
	finishWork()
}

func doStart() {
	postStatus("Starting the sensor…\r\nAllow Administrator if Windows asks.")
	svcreg := filepath.Join(platform.InstallDir(), "edr-svcreg.exe")
	_ = runElevated(12000, svcreg)
	if err := runElevated(45000, filepath.Join(platform.InstallDir(), "edrctl.exe"), "start"); err != nil {
		postStatus("Could not start the sensor.\r\n\r\n" + err.Error())
		setBusy(false)
		return
	}
	time.Sleep(400 * time.Millisecond)
	finishWork()
}

func doEnroll() {
	tok := tokenText()
	if tok == "" {
		postStatus("Paste an enrollment token, then click Enroll.")
		setBusy(false)
		return
	}
	postStatus("Enrolling this device…\r\nAllow Administrator if Windows asks.")
	if err := runElevated(60000, filepath.Join(platform.InstallDir(), "edrctl.exe"), "enroll", "--token", tok); err != nil {
		postStatus("Enrollment failed.\r\n\r\n" + err.Error())
		setBusy(false)
		return
	}
	_ = runElevated(45000, filepath.Join(platform.InstallDir(), "edrctl.exe"), "start")
	time.Sleep(400 * time.Millisecond)
	finishWork()
}

func runElevated(timeoutMs uint32, exe string, args ...string) error {
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("missing %s", exe)
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		cmd := exec.Command(exe, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg != "" {
				return fmt.Errorf("%v\n%s", err, msg)
			}
			return err
		}
		return nil
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	var params *uint16
	if line := quoteArgs(args); line != "" {
		params, _ = windows.UTF16PtrFromString(line)
	}
	info := shellExecuteInfo{
		FMask:        0x00000040,
		Hwnd:         hwndMain,
		LpVerb:       verb,
		LpFile:       file,
		LpParameters: params,
		NShow:        windows.SW_HIDE,
	}
	info.CbSize = uint32(unsafe.Sizeof(info))
	r, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		if callErr != nil {
			return callErr
		}
		return fmt.Errorf("Administrator approval was cancelled")
	}
	if info.HProcess == 0 {
		return nil
	}
	defer windows.CloseHandle(info.HProcess)
	if timeoutMs == 0 {
		timeoutMs = 30000
	}
	wait, _ := windows.WaitForSingleObject(info.HProcess, timeoutMs)
	if wait == waitTimeout {
		return fmt.Errorf("the request timed out. Try again, or run: edrctl %s", strings.Join(args, " "))
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.HProcess, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("elevated process exited %d", code)
	}
	return nil
}

func quoteArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = syscall.EscapeArg(a)
	}
	return strings.Join(parts, " ")
}

func logf(format string, args ...any) {
	dir := platform.LogDir()
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, "ui.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, time.Now().UTC().Format(time.RFC3339)+" winconsole "+format+"\n", args...)
}

func alert(title, body string) {
	t, _ := windows.UTF16PtrFromString(title)
	b, _ := windows.UTF16PtrFromString(body)
	user32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), 0x10)
}
