//go:build windows

package collector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows/registry"
)

const autorunsMaxClassSubkeys = 350
const autorunsMaxServices = 520

// AutorunsLiteSource enumerates a broad set of high-signal Windows persistence locations.
type AutorunsLiteSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	eventsTotal atomic.Uint64
	lastUnix    atomic.Int64

	cntRunKeys        atomic.Uint64
	cntExplorerRun    atomic.Uint64
	cntRunOnceEx      atomic.Uint64
	cntIFEO           atomic.Uint64
	cntSchtasks       atomic.Uint64
	cntAppInit        atomic.Uint64
	cntWinlogon       atomic.Uint64
	cntWinlogonNotify atomic.Uint64
	cntLSA            atomic.Uint64
	cntAppCert        atomic.Uint64
	cntKnownDLLs      atomic.Uint64
	cntBootExecute    atomic.Uint64
	cntShellHooks     atomic.Uint64
	cntBHO            atomic.Uint64
	cntPrintMon       atomic.Uint64
	cntServices       atomic.Uint64
	cntContextMenu    atomic.Uint64
}

func NewAutorunsLiteSource(endpointID, hostname string, cfg config.Config) *AutorunsLiteSource {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &AutorunsLiteSource{endpointID: endpointID, hostname: hostname, cfg: cfg}
}

func (s *AutorunsLiteSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "autoruns_lite",
		OS:            runtime.GOOS,
		Source:        "registry",
		Status:        "healthy",
		EPSOut:        s.eventsTotal.Load(),
		LastEventUnix: s.lastUnix.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.WindowsAutorunsLite
	src["autoruns_run_keys_emitted"] = s.cntRunKeys.Load()
	src["autoruns_explorer_run_emitted"] = s.cntExplorerRun.Load()
	src["autoruns_runonceex_emitted"] = s.cntRunOnceEx.Load()
	src["autoruns_ifeo_emitted"] = s.cntIFEO.Load()
	src["autoruns_tasks_emitted"] = s.cntSchtasks.Load()
	src["autoruns_appinit_emitted"] = s.cntAppInit.Load()
	src["autoruns_winlogon_emitted"] = s.cntWinlogon.Load()
	src["autoruns_winlogon_notify_emitted"] = s.cntWinlogonNotify.Load()
	src["autoruns_lsa_emitted"] = s.cntLSA.Load()
	src["autoruns_appcert_emitted"] = s.cntAppCert.Load()
	src["autoruns_knowndll_emitted"] = s.cntKnownDLLs.Load()
	src["autoruns_boot_execute_emitted"] = s.cntBootExecute.Load()
	src["autoruns_shell_hooks_emitted"] = s.cntShellHooks.Load()
	src["autoruns_bho_emitted"] = s.cntBHO.Load()
	src["autoruns_print_mon_emitted"] = s.cntPrintMon.Load()
	src["autoruns_services_emitted"] = s.cntServices.Load()
	src["autoruns_context_menu_emitted"] = s.cntContextMenu.Load()
	return src
}

func (s *AutorunsLiteSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.WindowsAutorunsLite {
		return nil
	}
	iv := s.cfg.Monitoring.WindowsAutorunsIntervalSec
	if iv <= 0 {
		iv = 300
	}
	t := time.NewTicker(time.Duration(iv) * time.Second)
	defer t.Stop()
	s.enumerate(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.enumerate(ctx, sink)
		}
	}
}

func (s *AutorunsLiteSource) enumerate(ctx context.Context, sink *StreamingSink) {
	now := time.Now().UTC()
	s.lastUnix.Store(now.Unix())

	runKeys := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`},
		// Explorer policy Run (BLUESPAWN T1547)
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	}
	for _, rk := range runKeys {
		if rk.path == `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` {
			s.emitRegistryValues(ctx, sink, rk.root, rk.path, "explorer_run_policies", now, func() { s.cntExplorerRun.Add(1) })
		} else {
			s.emitRegistryValues(ctx, sink, rk.root, rk.path, "run_key", now, func() { s.cntRunKeys.Add(1) })
		}
	}
	s.emitRunOnceEx(ctx, sink, registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`, now)
	s.emitRunOnceEx(ctx, sink, registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceServicesEx`, now)

	s.emitAppInitDLLs(ctx, sink, now)
	s.emitWinlogon(ctx, sink, now)
	s.emitWinlogonNotify(ctx, sink, now)
	s.emitLSA(ctx, sink, now)
	s.emitAppCertDLLs(ctx, sink, now)
	s.emitKnownDLLs(ctx, sink, now)
	s.emitBootExecute(ctx, sink, now)
	s.emitShellExecuteHooks(ctx, sink, now)
	s.emitBrowserHelpers(ctx, sink, now)
	s.emitPrintMonitors(ctx, sink, now)
	s.emitAutostartServices(ctx, sink, now)
	s.emitContextMenuHandlers(ctx, sink, now)

	s.emitIFEO(ctx, sink, now)
	s.emitSchtasks(ctx, sink, now)
}

func (s *AutorunsLiteSource) emitRegistryValues(ctx context.Context, sink *StreamingSink, root registry.Key, subpath, technique string, ts time.Time, bump func()) {
	k, err := registry.OpenKey(root, subpath, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		s.emitTagged(ctx, sink, technique, subpath+"\\"+name, val, ts,
			append([]string{"persistence", "windows-autorun", technique}),
			bump,
		)
	}
}

func (s *AutorunsLiteSource) emitRunOnceEx(ctx context.Context, sink *StreamingSink, root registry.Key, subpath string, ts time.Time) {
	k, err := registry.OpenKey(root, subpath, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil || strings.TrimSpace(val) == "" {
			continue
		}
		s.emitTagged(ctx, sink, "run_once_ex", subpath+"\\"+name, val, ts,
			[]string{"persistence", "windows-autorun", "run_once_ex"},
			func() { s.cntRunOnceEx.Add(1) },
		)
	}
	subs, _ := k.ReadSubKeyNames(-1)
	for _, skName := range subs {
		sk, err := registry.OpenKey(k, skName, registry.READ)
		if err != nil {
			continue
		}
		val, _, _ := sk.GetStringValue("")
		_ = sk.Close()
		if strings.TrimSpace(val) == "" {
			continue
		}
		s.emitTagged(ctx, sink, "run_once_ex", subpath+`\`+skName, val, ts,
			[]string{"persistence", "windows-autorun", "run_once_ex"},
			func() { s.cntRunOnceEx.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitAppInitDLLs(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	for _, name := range []string{"AppInit_DLLs", "LoadAppInit_DLLs"} {
		txt, _, err := k.GetStringValue(name)
		if err != nil || strings.TrimSpace(txt) == "" {
			continue
		}
		s.emitTagged(ctx, sink, "appinit", p+"\\"+name, txt, ts,
			[]string{"persistence", "windows-autorun", "appinit_dlls"},
			func() { s.cntAppInit.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitWinlogon(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	for _, name := range []string{"Userinit", "Shell", "Taskman"} {
		val, _, err := k.GetStringValue(name)
		if err != nil || strings.TrimSpace(val) == "" {
			continue
		}
		s.emitTagged(ctx, sink, "winlogon", p+"\\"+name, val, ts,
			[]string{"persistence", "windows-autorun", "winlogon"},
			func() { s.cntWinlogon.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitWinlogonNotify(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const base = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, sub := range subs {
		sk, err := registry.OpenKey(k, sub, registry.READ)
		if err != nil {
			continue
		}
		dll, _, err := sk.GetStringValue("DllName")
		_ = sk.Close()
		if err != nil || strings.TrimSpace(dll) == "" {
			continue
		}
		s.emitTagged(ctx, sink, "winlogon_notify", base+`\`+sub, dll, ts,
			[]string{"persistence", "windows-autorun", "winlogon_notify"},
			func() { s.cntWinlogonNotify.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitLSA(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SYSTEM\CurrentControlSet\Control\Lsa`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	for _, name := range []string{"Authentication Packages", "Notification Packages", "Security Packages"} {
		packs, _, err := k.GetStringsValue(name)
		if err != nil || len(packs) == 0 {
			continue
		}
		joined := strings.Join(packs, "|")
		s.emitTagged(ctx, sink, "lsa_packages", p+"\\"+name, joined, ts,
			[]string{"persistence", "windows-autorun", "lsa"},
			func() { s.cntLSA.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitAppCertDLLs(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil || strings.TrimSpace(val) == "" {
			continue
		}
		s.emitTagged(ctx, sink, "app_cert_dll", p+"\\"+name, val, ts,
			[]string{"persistence", "windows-autorun", "app_cert_dlls"},
			func() { s.cntAppCert.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitKnownDLLs(ctx context.Context, sink *StreamingSink, ts time.Time) {
	sysRoot := normalizeSystemRoot(os.Getenv("SystemRoot"))
	for _, leaf := range []string{`SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
		`SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32`} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, leaf, registry.READ)
		if err != nil {
			continue
		}
		names, err := k.ReadValueNames(-1)
		if err != nil {
			_ = k.Close()
			continue
		}
		for _, name := range names {
			val, _, err := k.GetStringValue(name)
			if err != nil || strings.TrimSpace(val) == "" {
				continue
			}
			exp := strings.ToLower(filepath.Clean(os.ExpandEnv(val)))
			sys32 := strings.ToLower(filepath.Clean(filepath.Join(sysRoot, "System32"))) + `\`
			if strings.HasPrefix(exp, sys32) {
				continue
			}
			s.emitTagged(ctx, sink, "knowndlls_outside_system32", leaf+"\\"+name, val, ts,
				[]string{"persistence", "windows-autorun", "knowndlls"},
				func() { s.cntKnownDLLs.Add(1) },
			)
		}
		_ = k.Close()
	}
}

func normalizeSystemRoot(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return `C:\Windows`
	}
	return s
}

func (s *AutorunsLiteSource) emitBootExecute(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SYSTEM\CurrentControlSet\Control\Session Manager`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	lines, _, err := k.GetStringsValue("BootExecute")
	if err != nil || len(lines) == 0 {
		return
	}
	joined := strings.Join(lines, "|")
	base := strings.ToLower(strings.Join(lines, " "))
	if base == strings.ToLower("autocheck autochk *") {
		return
	}
	s.emitTagged(ctx, sink, "boot_execute", p+`\BootExecute`, joined, ts,
		[]string{"persistence", "windows-autorun", "boot_execute"},
		func() { s.cntBootExecute.Add(1) },
	)
}

func (s *AutorunsLiteSource) emitShellExecuteHooks(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		guidOrVal := name
		txt, _, err := k.GetStringValue(name)
		if err != nil {
			txt = ""
		}
		txt = strings.TrimSpace(txt)
		if txt == "" {
			txt = guidOrVal
		}
		s.emitTagged(ctx, sink, "shell_execute_hooks", p+"\\"+name, txt, ts,
			[]string{"persistence", "windows-autorun", "shell_execute_hooks"},
			func() { s.cntShellHooks.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitBrowserHelpers(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, cls := range subs {
		sk, err := registry.OpenKey(k, cls, registry.READ)
		if err != nil {
			continue
		}
		val, _, err := sk.GetStringValue("")
		_ = sk.Close()
		desc := cls
		if err == nil && strings.TrimSpace(val) != "" {
			desc += "=" + strings.TrimSpace(val)
		}
		s.emitTagged(ctx, sink, "bho_cls", cls, desc, ts,
			[]string{"persistence", "windows-autorun", "bho"},
			func() { s.cntBHO.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitPrintMonitors(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const base = `SYSTEM\CurrentControlSet\Control\Print\Monitors`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, mon := range subs {
		sk, err := registry.OpenKey(k, mon, registry.READ)
		if err != nil {
			continue
		}
		driver, _, err := sk.GetStringValue("Driver")
		_ = sk.Close()
		if err != nil || strings.TrimSpace(driver) == "" {
			continue
		}
		s.emitTagged(ctx, sink, "print_monitor", base+`\`+mon+"\\Driver", driver, ts,
			[]string{"persistence", "windows-autorun", "print_monitor"},
			func() { s.cntPrintMon.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitAutostartServices(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const base = `SYSTEM\CurrentControlSet\Services`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	sysRoot := strings.ToLower(filepath.Clean(normalizeSystemRoot(os.Getenv("SystemRoot"))))
	nSeen := 0
	for _, name := range subs {
		if nSeen >= autorunsMaxServices || ctx.Err() != nil {
			break
		}
		sk, err := registry.OpenKey(k, name, registry.READ)
		if err != nil {
			continue
		}
		startVal, _, err := sk.GetIntegerValue("Start")
		if err != nil || startVal != 2 {
			_ = sk.Close()
			continue
		}
		imgRaw, _, imgErr := sk.GetStringValue("ImagePath")
		img := os.ExpandEnv(imgRaw)
		_ = sk.Close()
		if imgErr != nil || strings.TrimSpace(img) == "" {
			continue
		}
		exp := strings.ToLower(filepath.Clean(os.ExpandEnv(strings.TrimSpace(img))))
		if strings.HasPrefix(exp, sysRoot+`\`) {
			continue
		}
		nSeen++
		s.emitTagged(ctx, sink, "auto_start_service", base+`\`+name, img, ts,
			[]string{"persistence", "windows-autorun", "services"},
			func() { s.cntServices.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitContextMenuHandlers(ctx context.Context, sink *StreamingSink, ts time.Time) {
	for _, path := range []string{
		`SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers`,
		`SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`,
	} {
		s.emitContextMenuAt(ctx, sink, path, ts)
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes`, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for i, cls := range subs {
		if i >= autorunsMaxClassSubkeys || ctx.Err() != nil {
			break
		}
		sub := cls + `\shellex\ContextMenuHandlers`
		sk, err := registry.OpenKey(k, sub, registry.READ)
		if err != nil {
			continue
		}
		names, err := sk.ReadSubKeyNames(-1)
		_ = sk.Close()
		if err != nil {
			continue
		}
		for _, h := range names {
			s.emitTagged(ctx, sink, "context_menu", `SOFTWARE\Classes\`+sub+`\`+h, h, ts,
				[]string{"persistence", "windows-autorun", "context_menu"},
				func() { s.cntContextMenu.Add(1) },
			)
		}
	}
}

func (s *AutorunsLiteSource) emitContextMenuAt(ctx context.Context, sink *StreamingSink, fullPath string, ts time.Time) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, fullPath, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, h := range subs {
		if ctx.Err() != nil {
			return
		}
		s.emitTagged(ctx, sink, "context_menu", fullPath+`\`+h, h, ts,
			[]string{"persistence", "windows-autorun", "context_menu"},
			func() { s.cntContextMenu.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitIFEO(ctx context.Context, sink *StreamingSink, ts time.Time) {
	const p = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	for _, exe := range subs {
		sk, err := registry.OpenKey(k, exe, registry.READ)
		if err != nil {
			continue
		}
		dbg, _, _ := sk.GetStringValue("Debugger")
		_ = sk.Close()
		if strings.TrimSpace(dbg) == "" {
			continue
		}
		s.emitTagged(ctx, sink, "ifeo_debugger", p+`\`+exe, dbg, ts,
			[]string{"persistence", "windows-autorun", "ifeo_debugger"},
			func() { s.cntIFEO.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitSchtasks(ctx context.Context, sink *StreamingSink, ts time.Time) {
	if _, err := exec.LookPath("schtasks"); err != nil {
		return
	}
	cmd := exec.CommandContext(ctx, "schtasks", "/Query", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return
	}
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		fields := strings.Split(string(line), ",")
		if len(fields) < 2 {
			continue
		}
		name := strings.Trim(fields[0], `"`)
		if name == "" {
			continue
		}
		s.emitTagged(ctx, sink, "scheduled_task", "schtasks", name, ts,
			[]string{"persistence", "windows-autorun", "scheduled_task"},
			func() { s.cntSchtasks.Add(1) },
		)
	}
}

func (s *AutorunsLiteSource) emitTagged(ctx context.Context, sink *StreamingSink, technique, itemType, path string, ts time.Time, tags []string, bump func()) {
	s.eventsTotal.Add(1)
	if bump != nil {
		bump()
	}
	pe := &schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    s.endpointID,
			Timestamp:     ts,
			Hostname:      s.hostname,
			OS:            runtime.GOOS,
		},
		ProcessName: "windows_autorun",
		ProcessPath: itemType,
		CommandLine: technique + "=" + path,
		Tags:        tags,
	}
	if sink != nil {
		_ = sink.Send(ctx, Telemetry{Process: pe})
	}
}

