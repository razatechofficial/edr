//go:build windows

package actions

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// NetworkIsolateAction applies Windows Advanced Firewall rules with backup and optional timed rollback.
type NetworkIsolateAction struct {
	AllowList       []string
	DurationMinutes int
	BackupPath      string
	AgentIP         string // merged into allow list by caller
}

// PrepareCommands returns the netsh commands that would be run (for tests).
func (a *NetworkIsolateAction) PrepareCommands() []string {
	allow := MergeAllowList(a.AgentIP, a.AllowList)
	var cmds []string
	if a.BackupPath != "" {
		cmds = append(cmds, fmt.Sprintf(`netsh advfirewall export "%s"`, a.BackupPath))
	}
	cmds = append(cmds, `netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound`)
	for _, ip := range allow {
		if ip == "" {
			continue
		}
		cmds = append(cmds,
			fmt.Sprintf(`netsh advfirewall firewall add rule name="EDR-Allow" protocol=any remoteip=%s action=allow`, ip))
	}
	return cmds
}

// Execute applies isolation. Panic-safe. Restores from backup on rollback fn.
func (a *NetworkIsolateAction) Execute(ctx context.Context) (rollback func(context.Context) error, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("network_isolate panic: %v", r)
		}
	}()
	allow := MergeAllowList(a.AgentIP, a.AllowList)
	if a.BackupPath == "" {
		a.BackupPath = filepath.Join(os.TempDir(), "edr_fw_backup.wfw")
	}
	// Export current
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "export", a.BackupPath).Run()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound").Run()
	for _, ip := range allow {
		if ip == "" {
			continue
		}
		_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			`name=EDR-Allow`, "protocol=any", "remoteip="+ip, "action=allow").Run()
	}
	backup := a.BackupPath
	rollback = func(rctx context.Context) error {
		if backup == "" {
			return nil
		}
		return exec.CommandContext(rctx, "netsh", "advfirewall", "import", backup).Run()
	}
	if a.DurationMinutes > 0 && rollback != nil {
		rf := rollback
		time.AfterFunc(time.Duration(a.DurationMinutes)*time.Minute, func() {
			_ = rf(context.Background())
		})
	}
	return rollback, nil
}
