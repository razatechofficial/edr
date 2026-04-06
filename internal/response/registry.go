//go:build windows

package response

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/windows/registry"
)

// RegistryHandler implements ActionHandler for Windows registry remediation,
// including deletion of malicious keys and restoration of backed-up values.
type RegistryHandler struct {
	logger  *zap.Logger
	backups map[string]registryBackup
}

type registryBackup struct {
	Key       registry.Key
	Path      string
	ValueName string
	ValueType uint32
	Data      []byte
	BackedAt  time.Time
}

// NewRegistryHandler creates a handler for Windows registry operations.
func NewRegistryHandler(logger *zap.Logger) *RegistryHandler {
	return &RegistryHandler{
		logger:  logger,
		backups: make(map[string]registryBackup),
	}
}

// Execute deletes or restores registry keys/values.
// Params: "mode" ("delete"|"restore"), "hive" (string), "path" (string),
// "value_name" (string, optional for delete).
func (h *RegistryHandler) Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error) {
	mode := stringParam(params, "mode")
	if mode == "" {
		mode = "delete"
	}

	switch mode {
	case "delete":
		return h.deleteKey(params)
	case "restore":
		return h.restoreKey(params)
	default:
		return failResult(ActionRegistryDelete, fmt.Sprintf("unknown mode %q", mode)),
			fmt.Errorf("registry handler: unknown mode %q", mode)
	}
}

// Rollback restores any keys that were backed up during deletion.
func (h *RegistryHandler) Rollback(ctx context.Context, params map[string]interface{}) error {
	keyPath := stringParam(params, "path")
	backup, ok := h.backups[keyPath]
	if !ok {
		return fmt.Errorf("registry handler: no backup for %s", keyPath)
	}
	k, _, err := registry.CreateKey(backup.Key, backup.Path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("registry handler: create key for rollback: %w", err)
	}
	defer k.Close()

	if err := k.SetValue(backup.ValueName, backup.ValueType, backup.Data); err != nil {
		return fmt.Errorf("registry handler: restore value: %w", err)
	}
	delete(h.backups, keyPath)
	return nil
}

func (h *RegistryHandler) deleteKey(params map[string]interface{}) (*StepResult, error) {
	hiveName := stringParam(params, "hive")
	keyPath := stringParam(params, "path")
	valueName := stringParam(params, "value_name")

	if keyPath == "" {
		return failResult(ActionRegistryDelete, "registry path required"),
			fmt.Errorf("registry handler: path required")
	}

	hive, err := parseHive(hiveName)
	if err != nil {
		return failResult(ActionRegistryDelete, err.Error()), err
	}

	// Back up before deleting.
	k, err := registry.OpenKey(hive, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return failResult(ActionRegistryDelete, fmt.Sprintf("open key: %s", err)),
			fmt.Errorf("registry handler: open key %s: %w", keyPath, err)
	}
	defer k.Close()

	if valueName != "" {
		val, valType, err := k.GetValue(valueName, nil)
		if err == nil {
			buf := make([]byte, val)
			_, _, _ = k.GetValue(valueName, buf)
			h.backups[keyPath] = registryBackup{
				Key:       hive,
				Path:      keyPath,
				ValueName: valueName,
				ValueType: valType,
				Data:      buf,
				BackedAt:  time.Now(),
			}
		}
		if err := k.DeleteValue(valueName); err != nil {
			return failResult(ActionRegistryDelete, fmt.Sprintf("delete value: %s", err)),
				fmt.Errorf("registry handler: delete value %s\\%s: %w", keyPath, valueName, err)
		}
		return okResult(ActionRegistryDelete,
			fmt.Sprintf("deleted registry value %s\\%s", keyPath, valueName)), nil
	}

	// Delete the entire key.
	if err := registry.DeleteKey(hive, keyPath); err != nil {
		return failResult(ActionRegistryDelete, fmt.Sprintf("delete key: %s", err)),
			fmt.Errorf("registry handler: delete key %s: %w", keyPath, err)
	}
	return okResult(ActionRegistryDelete, fmt.Sprintf("deleted registry key %s", keyPath)), nil
}

func (h *RegistryHandler) restoreKey(params map[string]interface{}) (*StepResult, error) {
	keyPath := stringParam(params, "path")
	backup, ok := h.backups[keyPath]
	if !ok {
		return failResult(ActionRegistryRestore, "no backup found"),
			fmt.Errorf("registry handler: no backup for %s", keyPath)
	}

	k, _, err := registry.CreateKey(backup.Key, backup.Path, registry.SET_VALUE)
	if err != nil {
		return failResult(ActionRegistryRestore, err.Error()),
			fmt.Errorf("registry handler: create key: %w", err)
	}
	defer k.Close()

	if err := k.SetValue(backup.ValueName, backup.ValueType, backup.Data); err != nil {
		return failResult(ActionRegistryRestore, err.Error()),
			fmt.Errorf("registry handler: set value: %w", err)
	}
	delete(h.backups, keyPath)
	return okResult(ActionRegistryRestore,
		fmt.Sprintf("restored registry value %s\\%s", keyPath, backup.ValueName)), nil
}

func parseHive(name string) (registry.Key, error) {
	switch name {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, nil
	default:
		return 0, fmt.Errorf("registry handler: unsupported hive %q", name)
	}
}
