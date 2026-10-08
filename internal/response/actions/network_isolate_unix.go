//go:build linux || darwin

package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// NetworkIsolateAction applies host firewall policies (iptables on Linux, pf on Darwin). Not for production without review.
type NetworkIsolateAction struct {
	AllowList       []string
	DurationMinutes int
	BackupPath      string
	AgentIP         string
}

// PrepareCommands returns shell commands (for unit tests, no execution).
func (a *NetworkIsolateAction) PrepareCommands() []string {
	allow := MergeAllowList(a.AgentIP, a.AllowList)
	if runtime.GOOS == "darwin" {
		pf := []string{`pfctl -sr > ` + a.BackupPath + ` 2>/dev/null || true`}
		if a.BackupPath == "" {
			pf[0] = `pfctl -sr > /tmp/edr_pf_backup.txt 2>/dev/null || true`
		}
		return append(pf,
			`# edr_isolate anchor would be loaded from /etc/pf.anchors/edr_isolate`,
		)
	}
	var cmds []string
	if a.BackupPath != "" {
		cmds = append(cmds, fmt.Sprintf(`iptables-save > "%s"`, a.BackupPath))
	} else {
		cmds = append(cmds, `iptables-save > /tmp/edr_iptables.bak`)
	}
	cmds = append(cmds,
		`iptables -P INPUT DROP`,
		`iptables -P OUTPUT DROP`,
		`iptables -P FORWARD DROP`,
		`iptables -I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
		`iptables -I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`,
		`iptables -I INPUT -i lo -j ACCEPT`,
		`iptables -I OUTPUT -o lo -j ACCEPT`,
		// Keep remote SSH management channel available during isolation.
		`iptables -I INPUT -p tcp --dport 22 -j ACCEPT`,
		`iptables -I OUTPUT -p tcp --sport 22 -j ACCEPT`,
	)
	for _, ip := range allow {
		if ip == "" {
			continue
		}
		cmds = append(cmds,
			fmt.Sprintf(`iptables -I INPUT -s %s -j ACCEPT`, ip),
			fmt.Sprintf(`iptables -I OUTPUT -d %s -j ACCEPT`, ip),
		)
	}
	return cmds
}

// Execute runs iptables or pf helpers. Returns rollback that restores from backup.
func (a *NetworkIsolateAction) Execute(ctx context.Context) (rollback func(context.Context) error, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("network_isolate panic: %v", r)
		}
	}()
	allow := MergeAllowList(a.AgentIP, a.AllowList)
	if a.BackupPath == "" {
		// Not /tmp. A world-writable directory lets anyone pre-create the
		// backup as a symlink, and the old shell redirection would then
		// truncate whatever it pointed at, as root. systemd's PrivateTmp hid
		// that on Linux; launchd has no equivalent.
		a.BackupPath = defaultIsolateBackupPath()
	}
	if runtime.GOOS == "linux" {
		// Save the ruleset before changing it. If this fails, isolation does
		// not proceed: an isolation that cannot be reversed is a denial of
		// service the agent inflicts on its own host, and control-plane
		// commands carry no signature, so an attacker who can reach the
		// channel could use irreversible isolation as the attack itself.
		if err := saveIPTables(ctx, a.BackupPath); err != nil {
			return nil, fmt.Errorf("network_isolate: refusing to isolate without a restorable ruleset: %w", err)
		}
		_ = exec.CommandContext(ctx, "iptables", "-P", "INPUT", "DROP").Run()
		_ = exec.CommandContext(ctx, "iptables", "-P", "OUTPUT", "DROP").Run()
		_ = exec.CommandContext(ctx, "iptables", "-P", "FORWARD", "DROP").Run()
		_ = exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()
		_ = exec.CommandContext(ctx, "iptables", "-I", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()
		_ = exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-i", "lo", "-j", "ACCEPT").Run()
		_ = exec.CommandContext(ctx, "iptables", "-I", "OUTPUT", "-o", "lo", "-j", "ACCEPT").Run()
		_ = exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT").Run()
		_ = exec.CommandContext(ctx, "iptables", "-I", "OUTPUT", "-p", "tcp", "--sport", "22", "-j", "ACCEPT").Run()
		for _, ip := range allow {
			if ip == "" {
				continue
			}
			_ = exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-s", ip, "-j", "ACCEPT").Run()
			_ = exec.CommandContext(ctx, "iptables", "-I", "OUTPUT", "-d", ip, "-j", "ACCEPT").Run()
		}
		backup := a.BackupPath
		rollback = func(rctx context.Context) error {
			// A missing backup used to return nil, so releasing a host
			// reported success while leaving it isolated. Say so instead.
			if backup == "" {
				return fmt.Errorf("network_isolate: no backup path recorded; release the host manually")
			}
			if _, e := os.Lstat(backup); e != nil {
				return fmt.Errorf("network_isolate: ruleset backup %s is missing; release the host manually: %w", backup, e)
			}
			return restoreIPTables(rctx, backup)
		}
	} else {
		// BLOCKER: macOS isolation uses pf(4). A production agent must load a dedicated anchor
		// in /etc/pf.anchors (e.g. "edr_isolate") and reference it from /etc/pf.conf; toggling
		// global packet filter rules without operator review is unsafe. This path does not
		// run pfctl -E by default. Effective isolation typically requires running as root,
		// a persistent anchor file, and matching pfctl -f reload semantics; the PrepareCommands
		// list documents intended hook points. Rollback is a no-op here until a real anchor is wired.
		backup := a.BackupPath
		rollback = func(_ context.Context) error { return nil }
		_ = backup
	}
	if a.DurationMinutes > 0 && rollback != nil {
		rf := rollback
		time.AfterFunc(time.Duration(a.DurationMinutes)*time.Minute, func() {
			_ = rf(context.Background())
		})
	}
	return rollback, nil
}

// defaultIsolateBackupPath keeps the saved ruleset out of a shared directory.
func defaultIsolateBackupPath() string {
	if dir := strings.TrimSpace(os.Getenv("EDR_DATA_DIR")); dir != "" {
		return filepath.Join(dir, "iptables.bak")
	}
	return filepath.Join(os.TempDir(), "edr-isolate", "iptables.bak")
}

// saveIPTables writes the current ruleset without a shell.
//
// The file is opened O_EXCL|O_NOFOLLOW so an existing file — or a symlink
// planted where the backup will go — is refused rather than followed and
// truncated. Any stale backup is removed first, but only after confirming it is
// a regular file, so the removal cannot be aimed at something else.
func saveIPTables(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("backup path %s is not a regular file", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale backup: %w", err)
		}
	}
	// 0600: the ruleset describes the host's whole network posture.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, "iptables-save")
	cmd.Stdout = f
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables-save: %w", err)
	}
	return f.Sync()
}

// restoreIPTables reapplies a saved ruleset without a shell.
func restoreIPTables(ctx context.Context, path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open ruleset backup: %w", err)
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, "iptables-restore")
	cmd.Stdin = f
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables-restore: %w", err)
	}
	return nil
}
