//go:build windows

package kernel

import (
	"encoding/binary"
	"fmt"
)

// Versioned user-mode ↔ driver control-plane header (scaffolding; see docs/monitoring_minifilter_wfp_program.md).
const ControlPlaneProtocolVersion uint16 = 1

// ControlPlaneFramingMagic prefixes length-delimited control payloads on the wire.
const ControlPlaneFramingMagic uint16 = 0xED12

// MaxControlPlanePayloadBytes caps a single control message body.
const MaxControlPlanePayloadBytes = 64 * 1024

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

// BuildControlPlaneWire builds magic || version || command || payloadLen || payload (all LE).
func BuildControlPlaneWire(cmd ControlPlaneCommand, payload []byte) ([]byte, error) {
	if len(payload) > MaxControlPlanePayloadBytes {
		return nil, fmt.Errorf("control payload %d exceeds max %d", len(payload), MaxControlPlanePayloadBytes)
	}
	b := make([]byte, 12+len(payload))
	binary.LittleEndian.PutUint16(b[0:2], ControlPlaneFramingMagic)
	binary.LittleEndian.PutUint16(b[2:4], ControlPlaneProtocolVersion)
	binary.LittleEndian.PutUint32(b[4:8], uint32(cmd))
	binary.LittleEndian.PutUint32(b[8:12], uint32(len(payload)))
	copy(b[12:], payload)
	return b, nil
}
