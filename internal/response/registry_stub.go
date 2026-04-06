//go:build !windows

package response

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// RegistryHandler is a stub on non-Windows platforms. Registry remediation
// is only available on Windows.
type RegistryHandler struct {
	logger *zap.Logger
}

// NewRegistryHandler returns a stub handler on non-Windows platforms.
func NewRegistryHandler(logger *zap.Logger) *RegistryHandler {
	return &RegistryHandler{logger: logger}
}

// Execute returns an error on non-Windows platforms.
func (h *RegistryHandler) Execute(_ context.Context, _ map[string]interface{}) (*StepResult, error) {
	return failResult(ActionRegistryDelete, "registry operations only supported on Windows"),
		fmt.Errorf("registry handler: not supported on this platform")
}

// Rollback is a no-op on non-Windows platforms.
func (h *RegistryHandler) Rollback(_ context.Context, _ map[string]interface{}) error {
	return nil
}
