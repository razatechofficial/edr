package kernel

import (
	"errors"
	"fmt"
)

// Sentinel errors for monitoring/kernel tier orchestration and fallback triggers.
// Use errors.Is for branching.
var (
	ErrDriverSessionLost           = errors.New("kernel: driver session lost or externally stopped")
	ErrRingBufferSaturated         = errors.New("kernel: ring buffer full or saturated")
	ErrKernelUnavailable           = errors.New("kernel: kernel tier unavailable for this process or host")
	ErrMinifilterDriverNotPresent  = errors.New("kernel: minifilter driver or communication port not available")
	ErrWFPNotAvailable             = errors.New("kernel: Windows Filtering Platform engine or callouts not available")
	ErrNetworkExtensionUnavailable = errors.New("kernel: macOS Network Extension provider not loaded")
)

// WrapDriverSessionLost annotates err as a session-loss failure for errors.Is checks.
func WrapDriverSessionLost(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrDriverSessionLost, err)
}

// IsRingBufferSaturated reports whether err indicates ring buffer backpressure.
func IsRingBufferSaturated(err error) bool {
	return errors.Is(err, ErrRingBufferSaturated) || errors.Is(err, ErrBufferFull)
}
