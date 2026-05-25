//go:build windows

package kernel

// IOCTL codes shared with platform/windows/include/edr_ioctl.h
const (
	fileDeviceUnknown = 0x00000022
	methodBuffered    = 0
	fileAnyAccess     = 0
)

const (
	IOCTL_EDRAddProtectedPID    = (fileDeviceUnknown << 16) | (fileAnyAccess << 14) | (0x800 << 2) | methodBuffered
	IOCTL_EDRRemoveProtectedPID = (fileDeviceUnknown << 16) | (fileAnyAccess << 14) | (0x801 << 2) | methodBuffered
	IOCTL_EDRClearProtectedPIDs = (fileDeviceUnknown << 16) | (fileAnyAccess << 14) | (0x802 << 2) | methodBuffered
	IOCTL_EDRGetStatus          = (fileDeviceUnknown << 16) | (fileAnyAccess << 14) | (0x803 << 2) | methodBuffered
)

// DefaultWDMProtectDevice is the user-mode path for edr_protect.sys.
const DefaultWDMProtectDevice = `\\.\EdrProtect`

// WDMProtectStatus mirrors EDR_PROTECT_STATUS from edr_ioctl.h.
type WDMProtectStatus struct {
	ProtectedPidCount      uint32
	ObCallbacksRegistered  uint32
	Reserved               uint32
}
