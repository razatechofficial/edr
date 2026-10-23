package actions

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
)

// NetworkBlockAction blocks a specific IP/port (OS-specific implementation).
//
// Every field here originates in event data. A playbook substitutes values such
// as {{detection.event.dst_ip}} straight out of the observed event, and those
// values are influenced by whatever produced the event — which, in a detection
// product, routinely means an attacker. So the fields are validated before a
// command is built, and the commands are argument vectors rather than shell
// lines: there is no shell, so there is nothing to inject into.
type NetworkBlockAction struct {
	Direction       string
	DstIP           string
	DstPort         string
	DurationMinutes int
	RuleID          string
}

// ruleIDPattern bounds the rule identifier to characters that are safe in a
// firewall rule name on every supported platform.
var ruleIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Validate rejects anything that is not a real address, port or identifier.
//
// Rejecting is deliberately preferred to escaping: escaping has to be correct
// for each platform's shell, and getting it wrong fails open. A value that is
// not an IP address has no business reaching a firewall command at all.
func (a *NetworkBlockAction) Validate() error {
	if net.ParseIP(a.DstIP) == nil {
		return fmt.Errorf("network_block: %q is not a valid IP address", a.DstIP)
	}
	port, err := strconv.Atoi(a.DstPort)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("network_block: %q is not a valid port", a.DstPort)
	}
	if !ruleIDPattern.MatchString(a.RuleID) {
		return fmt.Errorf("network_block: rule id %q contains characters that are not permitted", a.RuleID)
	}
	return nil
}

// applyArgv returns the command that adds the rule, as program and arguments.
// A nil result means there is nothing safe to run: either this platform has no
// implementation, or the action did not validate.
//
// The validation check is deliberately repeated here rather than left to the
// caller. Every field in this action comes from event data a playbook
// substituted verbatim — {{detection.event.dst_ip}} and friends — so it is
// attacker-influenced, and an argv is one refactor away from being handed to a
// shell again. Refusing to build the command at all means an invalid value can
// never reach exec, whatever the caller forgot.
//
// Without it the darwin branch returned nil and so looked safe, while linux and
// windows embedded the raw value in an argument.
func (a *NetworkBlockAction) applyArgv() []string {
	if err := a.Validate(); err != nil {
		return nil
	}
	switch runtime.GOOS {
	case "windows":
		return []string{
			"netsh", "advfirewall", "firewall", "add", "rule",
			"name=EDR-Block-" + a.RuleID,
			"dir=out", "action=block",
			"remoteip=" + a.DstIP,
			"remoteport=" + a.DstPort,
		}
	case "darwin":
		// pf rules are applied through an anchor file rather than a one-liner.
		// There is no implementation here, and the previous comment-string
		// placeholder made a silent no-op look like a successful block.
		return nil
	default:
		return []string{
			"iptables", "-I", "OUTPUT",
			"-d", a.DstIP,
			"-p", "tcp", "--dport", a.DstPort,
			"-j", "DROP",
			"-m", "comment", "--comment", "edr-" + a.RuleID,
		}
	}
}

// rollbackArgv returns the command that removes the rule again.
// RollbackArgv is the command that lifts this block, exported so the caller can
// persist it. A rollback held only as a closure dies with the process, and the
// block outlives it.
func (a *NetworkBlockAction) RollbackArgv() []string { return a.rollbackArgv() }

func (a *NetworkBlockAction) rollbackArgv() []string {
	// Guarded for the same reason as applyArgv: these fields are
	// attacker-influenced, and a rollback that was never a valid block has
	// nothing to lift.
	if err := a.Validate(); err != nil {
		return nil
	}
	switch runtime.GOOS {
	case "windows":
		return []string{
			"netsh", "advfirewall", "firewall", "delete", "rule",
			"name=EDR-Block-" + a.RuleID,
		}
	case "darwin":
		return nil
	default:
		return []string{
			"iptables", "-D", "OUTPUT",
			"-d", a.DstIP,
			"-p", "tcp", "--dport", a.DstPort,
			"-j", "DROP",
		}
	}
}

func (a *NetworkBlockAction) buildRollback() func(context.Context) error {
	argv := a.rollbackArgv()
	if len(argv) < 2 {
		return nil
	}
	return func(rctx context.Context) error {
		return exec.CommandContext(rctx, argv[0], argv[1:]...).Run()
	}
}

// Execute applies the block. Returns a rollback (when apply is non-noop) and error.
func (a *NetworkBlockAction) Execute(ctx context.Context) (rollback func(context.Context) error, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("network_block panic: %v", r)
		}
	}()

	// Validate before anything is built, so a malformed value is refused rather
	// than blocked on a best-effort basis.
	if err = a.Validate(); err != nil {
		return nil, err
	}

	argv := a.applyArgv()
	if len(argv) < 2 {
		return nil, nil
	}
	if err = exec.CommandContext(ctx, argv[0], argv[1:]...).Run(); err != nil {
		return nil, err
	}
	return a.buildRollback(), nil
}
