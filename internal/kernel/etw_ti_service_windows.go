//go:build windows

package kernel

import (
	"errors"
)

// ensureTIPPLService is deprecated; AM-PPL is granted via MVI-signed user-mode
// service (launch_protected_tier=antimalware_light), not a helper service.
func ensureTIPPLService() error {
	return errors.New("kernel: ETW-TI full provider requires AM-PPL signed agent (MVI); see platform/windows/signing/pipeline.json")
}
