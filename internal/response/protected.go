package response

import (
	"path/filepath"
	"runtime"
	"strings"
)

// builtinProtected is the floor: processes this agent must never terminate,
// whatever a detection scores and whatever an operator configures.
//
// Shipped with the agent rather than left to configuration, which is how every
// serious endpoint product does it — Microsoft Defender, for instance, delivers
// predefined exclusions for operating-system and server-role processes through
// its own updates, separate from and in addition to anything an administrator
// sets. The reason is that an empty operator list must not mean an unprotected
// host, and the operator who most needs this floor is the one who has not
// thought about it yet.
//
// Everything here is a process whose death takes the machine with it or costs
// the user their session. Killing lsass.exe, csrss.exe or wininit.exe bugchecks
// Windows; killing launchd panics macOS; killing pid 1 panics Linux. An
// endpoint agent that can do any of those on a false positive is a denial of
// service shipped as a security control.
func builtinProtected() []string { return builtinProtectedFor(runtime.GOOS) }

// builtinProtectedFor takes the platform as an argument so every platform's
// list can be asserted from any host. A floor that is only ever checked on the
// developer's own operating system is two thirds unverified.
func builtinProtectedFor(goos string) []string {
	switch goos {
	case "windows":
		return []string{
			// Terminating any of these bugchecks the machine outright.
			"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
			"services.exe", "lsass.exe", "lsaiso.exe",
			// svchost hosts most of the OS; which services a given instance
			// carries is not knowable from the name, so none may be killed.
			"svchost.exe",
			// Session and shell: killing these does not crash the box but does
			// take the user's desktop with it.
			"dwm.exe", "fontdrvhost.exe", "explorer.exe", "logonui.exe",
			"userinit.exe", "sihost.exe", "ctfmon.exe",
			// Windows' own defender stack. An agent that can disable a peer
			// product is an attack tool.
			"msmpeng.exe", "mssense.exe", "mpdefendercoreservice.exe",
			"securityhealthservice.exe", "windefend.exe",
		}
	case "darwin":
		return []string{
			// pid 1 and the kernel's own task.
			"launchd", "kernel_task",
			// Window server and login: the user's session dies with them.
			"windowserver", "loginwindow", "dock", "finder", "systemuiserver",
			// Directory, security and configuration daemons. opendirectoryd or
			// securityd dying takes authentication with it.
			"opendirectoryd", "securityd", "trustd", "configd", "diskarbitrationd",
			"notifyd", "distnoted", "syslogd", "logd", "powerd", "coreaudiod",
			"mds", "mds_stores", "mdworker", "cfprefsd", "launchservicesd",
			// Apple's own endpoint security and update machinery.
			"endpointsecurityd", "syspolicyd", "tccd", "amfid", "softwareupdated",
			"xprotect", "xprotectservice", "mrt",
		}
	default:
		return []string{
			// pid 1 under any of its names, plus the kernel thread parent.
			"init", "systemd", "kthreadd", "upstart", "runit", "openrc-init",
			// Core systemd units. journald dying loses the audit trail that
			// would explain what this agent just did.
			"systemd-journald", "systemd-logind", "systemd-udevd",
			"systemd-networkd", "systemd-resolved", "systemd-oomd",
			// Login, session and remote access. Killing sshd on a headless
			// host locks everyone out of the machine the agent is defending.
			"sshd", "login", "getty", "agetty", "dbus-daemon", "dbus-broker",
			"polkitd", "accounts-daemon",
			// Audit and container runtimes: losing these loses either the
			// evidence or every workload on the node.
			"auditd", "rsyslogd", "containerd", "dockerd", "kubelet", "crio",
		}
	}
}

// protectedSet holds the floor plus whatever the operator added.
type protectedSet struct {
	// names are matched on the executable's base name, lower-cased. Coarse,
	// and a name is trivially forged, so it is a backstop rather than the
	// decision: a process claiming to be systemd is refused, which costs
	// nothing, while a genuinely malicious process that renames itself to
	// evade termination has only made itself conspicuous.
	names map[string]struct{}
	// paths are absolute, and are what an operator should prefer. A path is
	// not forgeable by a process choosing its own argv[0].
	paths map[string]struct{}
}

func newProtectedSet(operator []string) protectedSet {
	s := protectedSet{
		names: make(map[string]struct{}),
		paths: make(map[string]struct{}),
	}
	for _, v := range builtinProtected() {
		s.add(v)
	}
	for _, v := range operator {
		s.add(v)
	}
	return s
}

func (s protectedSet) add(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	// An entry that looks like a path is held as one, and also by its base
	// name so a match still happens when only the name is known.
	if strings.ContainsRune(v, filepath.Separator) {
		s.paths[normalisePath(v)] = struct{}{}
		s.names[strings.ToLower(filepath.Base(v))] = struct{}{}
		return
	}
	s.names[strings.ToLower(v)] = struct{}{}
}

// covers reports whether this target may not be terminated, and why.
func (s protectedSet) covers(name, path string) (string, bool) {
	if p := normalisePath(path); p != "" {
		if _, ok := s.paths[p]; ok {
			return "executable path is protected", true
		}
	}
	for _, candidate := range []string{name, path} {
		base := strings.ToLower(strings.TrimSpace(filepath.Base(strings.TrimSpace(candidate))))
		if base == "" || base == "." || base == string(filepath.Separator) {
			continue
		}
		if _, ok := s.names[base]; ok {
			return "process name is protected", true
		}
	}
	return "", false
}

// normalisePath lower-cases on the platforms whose filesystems are
// case-insensitive, and leaves Linux paths alone, where two paths differing in
// case are two different files.
func normalisePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(p)
	}
	return p
}
