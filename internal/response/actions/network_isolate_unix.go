//go:build linux || darwin

package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
		a.BackupPath = "/tmp/edr_iptables.bak"
	}
	if runtime.GOOS == "linux" {
		_ = exec.CommandContext(ctx, "sh", "-c", "iptables-save > "+a.BackupPath).Run()
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
			if backup == "" {
				return nil
			}
			if _, e := os.Stat(backup); e != nil {
				return nil
			}
			return exec.CommandContext(rctx, "sh", "-c", "iptables-restore < "+backup).Run()
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
