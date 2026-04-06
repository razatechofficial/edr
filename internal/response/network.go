package response

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"go.uber.org/zap"
)

// NetworkHandler implements ActionHandler for host-level network isolation and release.
// It manipulates firewall rules to block all traffic except loopback, the EDR
// server, and local DNS so that the agent can continue reporting.
type NetworkHandler struct {
	logger     *zap.Logger
	edrServer  string   // IP (or CIDR) of the EDR control-plane
	dnsServers []string // local DNS servers to allow
}

// NewNetworkHandler creates a handler that preserves connectivity to edrServerIP
// and the listed DNS servers while isolating the host from all other networks.
func NewNetworkHandler(logger *zap.Logger, edrServerIP string, dnsServers []string) *NetworkHandler {
	if len(dnsServers) == 0 {
		dnsServers = []string{"127.0.0.53", "127.0.0.1"}
	}
	return &NetworkHandler{
		logger:     logger,
		edrServer:  edrServerIP,
		dnsServers: dnsServers,
	}
}

// Execute applies network isolation or release depending on the "action" param.
// Params: "action" = "isolate"|"release".
func (h *NetworkHandler) Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error) {
	mode := stringParam(params, "action")
	if mode == "" {
		mode = "isolate"
	}

	switch mode {
	case "isolate":
		if err := h.isolate(ctx); err != nil {
			return failResult(ActionNetworkIsolate, err.Error()), err
		}
		return okResult(ActionNetworkIsolate, "host network isolated"), nil
	case "release":
		if err := h.release(ctx); err != nil {
			return failResult(ActionNetworkRelease, err.Error()), err
		}
		return okResult(ActionNetworkRelease, "host network released"), nil
	default:
		return failResult(ActionNetworkIsolate, fmt.Sprintf("unknown network mode %q", mode)),
			fmt.Errorf("network handler: unknown mode %q", mode)
	}
}

// Rollback reverses isolation by releasing all EDR firewall rules.
func (h *NetworkHandler) Rollback(ctx context.Context, _ map[string]interface{}) error {
	return h.release(ctx)
}

func (h *NetworkHandler) isolate(ctx context.Context) error {
	switch runtime.GOOS {
	case "linux":
		return h.isolateLinux(ctx)
	case "darwin":
		return h.isolateDarwin(ctx)
	case "windows":
		return h.isolateWindows(ctx)
	default:
		return fmt.Errorf("network handler: isolation not supported on %s", runtime.GOOS)
	}
}

func (h *NetworkHandler) release(ctx context.Context) error {
	switch runtime.GOOS {
	case "linux":
		return h.releaseLinux(ctx)
	case "darwin":
		return h.releaseDarwin(ctx)
	case "windows":
		return h.releaseWindows(ctx)
	default:
		return fmt.Errorf("network handler: release not supported on %s", runtime.GOOS)
	}
}

// ---------------------------------------------------------------------------
// Linux — iptables with a dedicated EDR chain
// ---------------------------------------------------------------------------

const iptablesChain = "EDR_ISOLATE"

func (h *NetworkHandler) isolateLinux(ctx context.Context) error {
	cmds := [][]string{
		// Create chain (ignore error if exists).
		{"iptables", "-N", iptablesChain},
		// Flush any prior rules.
		{"iptables", "-F", iptablesChain},
		// Allow loopback.
		{"iptables", "-A", iptablesChain, "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", iptablesChain, "-o", "lo", "-j", "ACCEPT"},
		// Allow established connections (so existing EDR TLS sessions survive).
		{"iptables", "-A", iptablesChain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		// Allow EDR server.
		{"iptables", "-A", iptablesChain, "-d", h.edrServer, "-j", "ACCEPT"},
		{"iptables", "-A", iptablesChain, "-s", h.edrServer, "-j", "ACCEPT"},
	}
	for _, dns := range h.dnsServers {
		cmds = append(cmds,
			[]string{"iptables", "-A", iptablesChain, "-d", dns, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
			[]string{"iptables", "-A", iptablesChain, "-d", dns, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		)
	}
	// Default drop.
	cmds = append(cmds,
		[]string{"iptables", "-A", iptablesChain, "-j", "DROP"},
		// Insert jump from INPUT/OUTPUT.
		[]string{"iptables", "-I", "INPUT", "1", "-j", iptablesChain},
		[]string{"iptables", "-I", "OUTPUT", "1", "-j", iptablesChain},
	)

	for _, args := range cmds {
		if err := runCmd(ctx, args[0], args[1:]...); err != nil {
			// -N may fail if chain exists; that's expected.
			if !(args[1] == "-N" && strings.Contains(err.Error(), "already exists")) {
				h.logger.Warn("iptables command failed", zap.Strings("cmd", args), zap.Error(err))
			}
		}
	}
	return nil
}

func (h *NetworkHandler) releaseLinux(ctx context.Context) error {
	cmds := [][]string{
		{"iptables", "-D", "INPUT", "-j", iptablesChain},
		{"iptables", "-D", "OUTPUT", "-j", iptablesChain},
		{"iptables", "-F", iptablesChain},
		{"iptables", "-X", iptablesChain},
	}
	for _, args := range cmds {
		_ = runCmd(ctx, args[0], args[1:]...) // best-effort
	}
	return nil
}

// ---------------------------------------------------------------------------
// macOS — pfctl with an EDR anchor
// ---------------------------------------------------------------------------

const pfAnchor = "com.edr.isolate"

func (h *NetworkHandler) isolateDarwin(ctx context.Context) error {
	var rules strings.Builder
	rules.WriteString("# EDR isolation rules\n")
	rules.WriteString("pass on lo0 all\n")
	rules.WriteString(fmt.Sprintf("pass out proto {tcp, udp} to %s\n", h.edrServer))
	rules.WriteString(fmt.Sprintf("pass in proto {tcp, udp} from %s\n", h.edrServer))
	for _, dns := range h.dnsServers {
		rules.WriteString(fmt.Sprintf("pass out proto {tcp, udp} to %s port 53\n", dns))
	}
	rules.WriteString("block all\n")

	cmd := exec.CommandContext(ctx, "pfctl", "-a", pfAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl load anchor: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if err := runCmd(ctx, "pfctl", "-e"); err != nil {
		h.logger.Warn("pfctl enable may have failed (possibly already enabled)", zap.Error(err))
	}
	return nil
}

func (h *NetworkHandler) releaseDarwin(ctx context.Context) error {
	_ = runCmd(ctx, "pfctl", "-a", pfAnchor, "-F", "all")
	return nil
}

// ---------------------------------------------------------------------------
// Windows — netsh advfirewall
// ---------------------------------------------------------------------------

const netshRulePrefix = "EDR_ISOLATE"

func (h *NetworkHandler) isolateWindows(ctx context.Context) error {
	// Block all inbound/outbound, then allow exceptions.
	cmds := [][]string{
		{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
		// Allow EDR server.
		{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=" + netshRulePrefix + "_EDR_OUT", "dir=out", "action=allow",
			"remoteip=" + h.edrServer, "enable=yes"},
		{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=" + netshRulePrefix + "_EDR_IN", "dir=in", "action=allow",
			"remoteip=" + h.edrServer, "enable=yes"},
		// Allow loopback.
		{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=" + netshRulePrefix + "_LO_OUT", "dir=out", "action=allow",
			"remoteip=127.0.0.1", "enable=yes"},
	}
	for i, dns := range h.dnsServers {
		cmds = append(cmds, []string{
			"netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s_DNS_%d", netshRulePrefix, i), "dir=out", "action=allow",
			"remoteip=" + dns, "remoteport=53", "protocol=udp", "enable=yes",
		})
	}
	for _, args := range cmds {
		if err := runCmd(ctx, args[0], args[1:]...); err != nil {
			h.logger.Warn("netsh command failed", zap.Strings("cmd", args), zap.Error(err))
		}
	}
	return nil
}

func (h *NetworkHandler) releaseWindows(ctx context.Context) error {
	cmds := [][]string{
		{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"},
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + netshRulePrefix + "_EDR_OUT"},
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + netshRulePrefix + "_EDR_IN"},
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + netshRulePrefix + "_LO_OUT"},
	}
	// Remove DNS rules.
	for i := range h.dnsServers {
		cmds = append(cmds, []string{
			"netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=%s_DNS_%d", netshRulePrefix, i),
		})
	}
	for _, args := range cmds {
		_ = runCmd(ctx, args[0], args[1:]...) // best-effort
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func runCmd(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
