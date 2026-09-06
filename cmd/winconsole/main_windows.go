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
	"syscall"
	"time"
	"unsafe"

	"github.com/razatechofficial/edr/internal/hostperm"
	"github.com/razatechofficial/edr/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsTabstop     = 0x00010000
	wsBorder      = 0x00800000
	wsVscroll     = 0x00200000
	esMultiline   = 0x0004
	esAutovscroll = 0x0040
	esReadonly    = 0x0800
	esAutohscroll = 0x0080
	idStatus      = 1001
	idToken       = 1002
	idEnroll      = 1003
	idStart       = 1004
	idRepair      = 1005
	idRecheck     = 1006
	wmCommand     = 0x0111
	wmDestroy     = 0x0002
	wmSetText     = 0x000C
	wmGetText     = 0x000D
	wmGetTextLen  = 0x000E
	colorWindow   = 5
	swShow        = 5
)

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procSetWindowTextW   = user32.NewProc("SetWindowTextW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetSysColorBrush = user32.NewProc("GetSysColorBrush")
	procSetFocus         = user32.NewProc("SetFocus")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procShellExecuteExW  = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

	hwndStatus windows.Handle
	hwndToken  windows.Handle
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

func main() {
	logf("winconsole start args=%v", os.Args)
	if err := runWindow(); err != nil {
		logf("fatal: %v", err)
		alert("EDR Agent", err.Error())
		os.Exit(1)
	}
}

func runWindow() error {
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
		if last != 1410 { // ERROR_CLASS_ALREADY_EXISTS
			return fmt.Errorf("register window class: %v", err)
		}
	}
	hwnd, _, err := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)),
		0x00CF0000, // WS_OVERLAPPEDWINDOW
		200, 120, 560, 460,
		0, 0, uintptr(inst), 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("create window: %v", err)
	}
	procShowWindow.Call(hwnd, swShow)
	procUpdateWindow.Call(hwnd)
	refresh()
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
	case wmCommand:
		switch uint16(wParam) {
		case idEnroll:
			go doEnroll()
		case idStart:
			go doStart()
		case idRepair:
			go doRepair()
		case idRecheck:
			refresh()
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
	hwndStatus = createCtl(parent, "EDIT", "", idStatus, 16, 16, 512, 210, wsVisible|wsChild|wsBorder|wsVscroll|esMultiline|esAutovscroll|esReadonly)
	createCtl(parent, "STATIC", "Enrollment token", 1099, 16, 236, 512, 18, wsVisible|wsChild)
	hwndToken = createCtl(parent, "EDIT", "", idToken, 16, 256, 512, 28, wsVisible|wsChild|wsTabstop|wsBorder|esAutohscroll)
	createCtl(parent, "BUTTON", "Enroll", idEnroll, 16, 300, 120, 32, wsVisible|wsChild|wsTabstop)
	createCtl(parent, "BUTTON", "Start sensor", idStart, 148, 300, 120, 32, wsVisible|wsChild|wsTabstop)
	createCtl(parent, "BUTTON", "Repair service", idRepair, 280, 300, 130, 32, wsVisible|wsChild|wsTabstop)
	createCtl(parent, "BUTTON", "Recheck", idRecheck, 422, 300, 106, 32, wsVisible|wsChild|wsTabstop)
	procSetFocus.Call(uintptr(hwndToken))
}

func createCtl(parent windows.Handle, class, text string, id int, x, y, w, h int, style uint32) windows.Handle {
	cls, _ := windows.UTF16PtrFromString(class)
	txt, _ := windows.UTF16PtrFromString(text)
	hwnd, _, _ := procCreateWindowExW.Call(
		0x200, // WS_EX_CLIENTEDGE for edit/status
		uintptr(unsafe.Pointer(cls)),
		uintptr(unsafe.Pointer(txt)),
		uintptr(style),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		uintptr(parent), uintptr(id), 0, 0,
	)
	return windows.Handle(hwnd)
}

func setStatus(s string) {
	if hwndStatus == 0 {
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

func refresh() {
	setStatus(collectStatus())
}

func collectStatus() string {
	var b strings.Builder
	b.WriteString("EDR Agent  (works on Windows 10/11/Server without OpenGL)\r\n\r\n")
	svcName, startType := serviceSnapshot()
	b.WriteString("Service:  " + svcName)
	if startType != "" {
		b.WriteString("  (" + startType + ")")
	}
	b.WriteString("\r\n")
	enrolled, agentID := enrollmentSnapshot()
	if enrolled {
		b.WriteString("Enroll:   enrolled")
		if agentID != "" {
			b.WriteString("  id=" + agentID)
		}
		b.WriteString("\r\n")
	} else {
		b.WriteString("Enroll:   not enrolled  (paste a token and Enroll)\r\n")
	}
	if hostperm.SensorRegistered() {
		b.WriteString("SCM:      EDRAgent is registered\r\n")
	} else {
		b.WriteString("SCM:      EDRAgent missing  (Repair service)\r\n")
	}
	b.WriteString("\r\nLogs: %ProgramData%\\EDR Agent\\logs\\ui.log\r\n")
	return b.String()
}

func serviceSnapshot() (state, startType string) {
	m, err := mgr.Connect()
	if err != nil {
		return "unavailable", ""
	}
	defer m.Disconnect()
	s, err := m.OpenService("EDRAgent")
	if err != nil {
		return "not installed", ""
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "unknown", ""
	}
	cfg, _ := s.Config()
	switch cfg.StartType {
	case mgr.StartAutomatic:
		startType = "Automatic"
	case mgr.StartDisabled:
		startType = "Disabled"
	case mgr.StartManual:
		startType = "Manual"
	}
	switch st.State {
	case svc.Running:
		return "running", startType
	case svc.Stopped:
		return "stopped", startType
	case svc.StartPending:
		return "starting", startType
	default:
		return fmt.Sprintf("state %d", st.State), startType
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

func doRepair() {
	setStatus("Registering EDRAgent…")
	exe := filepath.Join(platform.InstallDir(), "edr-agent.exe")
	cfg := filepath.Join(platform.DataDir(), "config.yml")
	if err := hostperm.EnsureSensorService(exe, cfg); err != nil {
		if err := runElevated(filepath.Join(platform.InstallDir(), "edr-svcreg.exe")); err != nil {
			setStatus("Repair failed:\r\n" + err.Error() + "\r\n\r\nAllow Administrator if prompted.")
			return
		}
	}
	time.Sleep(400 * time.Millisecond)
	refresh()
}

func doStart() {
	setStatus("Starting EDRAgent…")
	if !hostperm.SensorRegistered() {
		doRepair()
	}
	if err := runElevated(filepath.Join(platform.InstallDir(), "edrctl.exe"), "start"); err != nil {
		setStatus("Start failed:\r\n" + err.Error())
		return
	}
	time.Sleep(800 * time.Millisecond)
	refresh()
}

func doEnroll() {
	tok := tokenText()
	if tok == "" {
		setStatus("Paste an enrollment token, then Enroll.")
		return
	}
	setStatus("Enrolling…")
	if err := runElevated(filepath.Join(platform.InstallDir(), "edrctl.exe"), "enroll", "--token", tok); err != nil {
		setStatus("Enroll failed:\r\n" + err.Error())
		return
	}
	_ = runElevated(filepath.Join(platform.InstallDir(), "edrctl.exe"), "start")
	time.Sleep(800 * time.Millisecond)
	refresh()
}

func runElevated(exe string, args ...string) error {
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
		FMask:        0x00000040, // SEE_MASK_NOCLOSEPROCESS
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
		return fmt.Errorf("UAC elevation failed")
	}
	if info.HProcess == 0 {
		return nil
	}
	defer windows.CloseHandle(info.HProcess)
	_, _ = windows.WaitForSingleObject(info.HProcess, windows.INFINITE)
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
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	dir := filepath.Join(pd, "EDR Agent", "logs")
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
