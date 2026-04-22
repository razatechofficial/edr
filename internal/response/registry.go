//go:build windows

package response

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"

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

	if err := setRegistryValue(k, backup.ValueName, backup.ValueType, backup.Data); err != nil {
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

	if err := setRegistryValue(k, backup.ValueName, backup.ValueType, backup.Data); err != nil {
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

func setRegistryValue(k registry.Key, name string, valueType uint32, data []byte) error {
	switch valueType {
	case registry.DWORD:
		if len(data) < 4 {
			return fmt.Errorf("invalid DWORD data length: %d", len(data))
		}
		return k.SetDWordValue(name, binary.LittleEndian.Uint32(data[:4]))
	case registry.QWORD:
		if len(data) < 8 {
			return fmt.Errorf("invalid QWORD data length: %d", len(data))
		}
		return k.SetQWordValue(name, binary.LittleEndian.Uint64(data[:8]))
	case registry.SZ:
		return k.SetStringValue(name, decodeUTF16Bytes(data))
	case registry.EXPAND_SZ:
		return k.SetExpandStringValue(name, decodeUTF16Bytes(data))
	case registry.MULTI_SZ:
		return k.SetStringsValue(name, decodeUTF16MultiString(data))
	default:
		return k.SetBinaryValue(name, data)
	}
}

func decodeUTF16Bytes(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i : i+2])
		if v == 0 {
			break
		}
		u16 = append(u16, v)
	}
	return string(utf16.Decode(u16))
}

func decodeUTF16MultiString(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	var out []string
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i : i+2])
		u16 = append(u16, v)
	}
	cur := make([]uint16, 0, len(u16))
	for _, v := range u16 {
		if v == 0 {
			if len(cur) == 0 {
				break
			}
			out = append(out, string(utf16.Decode(cur)))
			cur = cur[:0]
			continue
		}
		cur = append(cur, v)
	}
	return out
}
