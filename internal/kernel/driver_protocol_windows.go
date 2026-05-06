//go:build windows

package kernel

// Versioned user-mode ↔ driver control-plane header (scaffolding; see docs/monitoring_minifilter_wfp_program.md).
const ControlPlaneProtocolVersion uint16 = 1

// ControlPlaneCommand identifies IOCTL-class operations for a future signed minifilter/WFP companion.
type ControlPlaneCommand uint32

const (
	CmdDriverStart ControlPlaneCommand = 0x100
	CmdDriverStop  ControlPlaneCommand = 0x101
	CmdSetConfig   ControlPlaneCommand = 0x110
	CmdUpdateRules ControlPlaneCommand = 0x120
)

// ControlPlaneHeader is the wire prefix for binary control payloads.
type ControlPlaneHeader struct {
	Version uint16
	_       uint16 // reserved / padding
	Command uint32
}
