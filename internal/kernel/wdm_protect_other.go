//go:build !windows

package kernel

// WDMProtectStatus is unused on non-Windows builds.
type WDMProtectStatus struct {
	ProtectedPidCount     uint32
	ObCallbacksRegistered uint32
}

// WDMProtect is a stub on non-Windows builds.
type WDMProtect struct{}

// GlobalWDMProtect returns a stub client on non-Windows builds.
func GlobalWDMProtect() *WDMProtect { return &WDMProtect{} }

func (w *WDMProtect) SetDevice(string) {}
func (w *WDMProtect) Health() map[string]any {
	return map[string]any{"supported": false}
}

// RegisterCurrentProcessWithWDM is a no-op on non-Windows builds.
func RegisterCurrentProcessWithWDM() map[string]any {
	return map[string]any{"supported": false}
}
