package actions

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// NetworkBlockAction blocks a specific IP/port (OS-specific implementation).
type NetworkBlockAction struct {
	Direction       string
	DstIP           string
	DstPort         string
	DurationMinutes int
	RuleID          string
}

// RollbackCommands returns commands to remove the rule.
func (a *NetworkBlockAction) RollbackCommands() []string {
	switch runtime.GOOS {
	case "windows":
		if a.RuleID == "" {
			return nil
		}
		return []string{fmt.Sprintf(`netsh advfirewall firewall delete rule name="EDR-Block-%s"`, a.RuleID)}
	case "darwin":
		return []string{fmt.Sprintf(`# pf: remove edr block %s`, a.RuleID)}
	default:
		return []string{fmt.Sprintf(`iptables -D OUTPUT -d %s -p tcp --dport %s -j DROP`, a.DstIP, a.DstPort)}
	}
}

// ApplyCommands returns add-rule command lines.
func (a *NetworkBlockAction) ApplyCommands() []string {
	switch runtime.GOOS {
	case "windows":
		if a.RuleID == "" {
			return nil
		}
		return []string{fmt.Sprintf(
			`netsh advfirewall firewall add rule name="EDR-Block-%s" dir=out action=block remoteip=%s remoteport=%s`,
			a.RuleID, a.DstIP, a.DstPort,
		)}
	case "darwin":
		return []string{fmt.Sprintf(`# pf: block %s -> %s:%s id=%s`, a.DstIP, a.DstIP, a.DstPort, a.RuleID)}
	default:
		if a.RuleID == "" {
			return nil
		}
		return []string{fmt.Sprintf(
			`iptables -I OUTPUT -d %s -p tcp --dport %s -j DROP -m comment --comment "edr-%s"`,
			a.DstIP, a.DstPort, a.RuleID,
		)}
	}
}

// Execute applies the block (panic-safe; may no-op on unsupported).
func (a *NetworkBlockAction) Execute(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("network_block panic: %v", r)
		}
	}()
	cmds := a.ApplyCommands()
	if len(cmds) == 0 {
		return nil
	}
	line := strings.TrimSpace(cmds[0])
	if strings.HasPrefix(line, "#") {
		return nil
	}
	if runtime.GOOS == "windows" {
		fs := strings.Fields(line)
		if len(fs) < 2 {
			return nil
		}
		return exec.CommandContext(ctx, fs[0], fs[1:]...).Run()
	}
	return exec.CommandContext(ctx, "sh", "-c", line).Run()
}
