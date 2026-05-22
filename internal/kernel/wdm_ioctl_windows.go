//go:build windows

package kernel

// IOCTL codes shared with platform/windows/include/edr_ioctl.h
const (
	fileDeviceUnknown = 0x00000022
	methodBuffered    = 0
	fileAnyAccess     = 0
)

func ctlCode(deviceType, function, method, access uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

const (
	IOCTL_EDRAddProtectedPID    = ctlCode(fileDeviceUnknown, 0x800, methodBuffered, fileAnyAccess)
	IOCTL_EDRRemoveProtectedPID = ctlCode(fileDeviceUnknown, 0x801, methodBuffered, fileAnyAccess)
	IOCTL_EDRClearProtectedPIDs = ctlCode(fileDeviceUnknown, 0x802, methodBuffered, fileAnyAccess)
	IOCTL_EDRGetStatus          = ctlCode(fileDeviceUnknown, 0x803, methodBuffered, fileAnyAccess)
)

// DefaultWDMProtectDevice is the user-mode path for edr_protect.sys.
const DefaultWDMProtectDevice = `\\.\EdrProtect`

// WDMProtectStatus mirrors EDR_PROTECT_STATUS from edr_ioctl.h.
type WDMProtectStatus struct {
	ProtectedPidCount      uint32
	ObCallbacksRegistered  uint32
	Reserved               uint32
}
