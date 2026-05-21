//go:build !windows

package sca

import "fmt"

func evalRegistryRule(_, _ string) (bool, error) {
	return false, fmt.Errorf("sca: registry rules require windows")
}
