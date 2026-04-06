package response

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SnapshotHandler implements ActionHandler for filesystem snapshot creation
// and restoration. It uses LVM/btrfs on Linux, APFS snapshots on macOS,
// and VSS on Windows.
type SnapshotHandler struct {
	logger *zap.Logger
}

// NewSnapshotHandler creates a handler for system snapshot operations.
func NewSnapshotHandler(logger *zap.Logger) *SnapshotHandler {
	return &SnapshotHandler{logger: logger}
}

// Execute creates or restores a snapshot based on the "mode" param.
// Params: "mode" ("create"|"restore"), "name" (string, optional),
// "volume" (string, optional - LVM VG/LV or mount point).
func (h *SnapshotHandler) Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error) {
	mode := stringParam(params, "mode")
	if mode == "" {
		mode = "create"
	}

	name := stringParam(params, "name")
	if name == "" {
		name = fmt.Sprintf("edr_snap_%s", time.Now().UTC().Format("20060102T150405Z"))
	}

	switch mode {
	case "create":
		return h.create(ctx, name, params)
	case "restore":
		return h.restore(ctx, name, params)
	default:
		return failResult(ActionSnapshot, fmt.Sprintf("unknown mode %q", mode)),
			fmt.Errorf("snapshot handler: unknown mode %q", mode)
	}
}

// Rollback deletes a previously created snapshot.
func (h *SnapshotHandler) Rollback(ctx context.Context, params map[string]interface{}) error {
	name := stringParam(params, "name")
	if name == "" {
		return fmt.Errorf("snapshot rollback: name required")
	}

	switch runtime.GOOS {
	case "linux":
		return h.deleteLinux(ctx, name, params)
	case "darwin":
		return h.deleteDarwin(ctx, name)
	case "windows":
		return h.deleteWindows(ctx, name)
	default:
		return fmt.Errorf("snapshot rollback: unsupported on %s", runtime.GOOS)
	}
}

func (h *SnapshotHandler) create(ctx context.Context, name string, params map[string]interface{}) (*StepResult, error) {
	switch runtime.GOOS {
	case "linux":
		return h.createLinux(ctx, name, params)
	case "darwin":
		return h.createDarwin(ctx, name)
	case "windows":
		return h.createWindows(ctx, name)
	default:
		return failResult(ActionSnapshot, fmt.Sprintf("unsupported on %s", runtime.GOOS)),
			fmt.Errorf("snapshot handler: unsupported on %s", runtime.GOOS)
	}
}

func (h *SnapshotHandler) restore(ctx context.Context, name string, params map[string]interface{}) (*StepResult, error) {
	switch runtime.GOOS {
	case "linux":
		return h.restoreLinux(ctx, name, params)
	case "darwin":
		return h.restoreDarwin(ctx, name)
	case "windows":
		return h.restoreWindows(ctx, name)
	default:
		return failResult(ActionSnapshot, fmt.Sprintf("unsupported on %s", runtime.GOOS)),
			fmt.Errorf("snapshot handler: unsupported on %s", runtime.GOOS)
	}
}

// ---------------------------------------------------------------------------
// Linux — LVM snapshots (fallback to btrfs)
// ---------------------------------------------------------------------------

func (h *SnapshotHandler) createLinux(ctx context.Context, name string, params map[string]interface{}) (*StepResult, error) {
	volume := stringParam(params, "volume")

	// Try btrfs first if volume looks like a mount point.
	if volume != "" && !strings.Contains(volume, "/") {
		// Looks like an LVM LV name, use lvcreate.
		return h.createLVM(ctx, name, volume)
	}
	if volume == "" {
		volume = "/"
	}

	// Detect filesystem type.
	fsType, _ := detectFS(ctx, volume)
	switch fsType {
	case "btrfs":
		return h.createBtrfs(ctx, name, volume)
	default:
		return h.createLVM(ctx, name, volume)
	}
}

func (h *SnapshotHandler) createLVM(ctx context.Context, name, lv string) (*StepResult, error) {
	// lvcreate --snapshot --name <name> --size 5G <vg/lv>
	args := []string{"--snapshot", "--name", name, "--size", "5G", lv}
	if err := runCmd(ctx, "lvcreate", args...); err != nil {
		return failResult(ActionSnapshot, err.Error()),
			fmt.Errorf("snapshot handler: lvcreate: %w", err)
	}
	return okResult(ActionSnapshot, fmt.Sprintf("LVM snapshot %q created for %s", name, lv)), nil
}

func (h *SnapshotHandler) createBtrfs(ctx context.Context, name, mountPoint string) (*StepResult, error) {
	snapPath := mountPoint + "/.snapshots/" + name
	if err := runCmd(ctx, "btrfs", "subvolume", "snapshot", "-r", mountPoint, snapPath); err != nil {
		return failResult(ActionSnapshot, err.Error()),
			fmt.Errorf("snapshot handler: btrfs snapshot: %w", err)
	}
	return okResult(ActionSnapshot, fmt.Sprintf("btrfs snapshot created at %s", snapPath)), nil
}

func (h *SnapshotHandler) restoreLinux(ctx context.Context, name string, params map[string]interface{}) (*StepResult, error) {
	volume := stringParam(params, "volume")
	fsType, _ := detectFS(ctx, volume)
	switch fsType {
	case "btrfs":
		snapPath := volume + "/.snapshots/" + name
		if err := runCmd(ctx, "btrfs", "subvolume", "snapshot", snapPath, volume+".restored"); err != nil {
			return failResult(ActionSnapshot, err.Error()), fmt.Errorf("snapshot handler: btrfs restore: %w", err)
		}
		return okResult(ActionSnapshot, fmt.Sprintf("btrfs snapshot %q restored", name)), nil
	default:
		// LVM merge.
		if err := runCmd(ctx, "lvconvert", "--merge", name); err != nil {
			return failResult(ActionSnapshot, err.Error()), fmt.Errorf("snapshot handler: lvconvert merge: %w", err)
		}
		return okResult(ActionSnapshot, fmt.Sprintf("LVM snapshot %q merge initiated", name)), nil
	}
}

func (h *SnapshotHandler) deleteLinux(ctx context.Context, name string, params map[string]interface{}) error {
	volume := stringParam(params, "volume")
	fsType, _ := detectFS(ctx, volume)
	switch fsType {
	case "btrfs":
		return runCmd(ctx, "btrfs", "subvolume", "delete", volume+"/.snapshots/"+name)
	default:
		return runCmd(ctx, "lvremove", "-f", name)
	}
}

func detectFS(ctx context.Context, mountPoint string) (string, error) {
	if mountPoint == "" {
		mountPoint = "/"
	}
	out, err := exec.CommandContext(ctx, "stat", "-f", "-c", "%T", mountPoint).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ---------------------------------------------------------------------------
// macOS — APFS snapshot via tmutil
// ---------------------------------------------------------------------------

func (h *SnapshotHandler) createDarwin(ctx context.Context, name string) (*StepResult, error) {
	if err := runCmd(ctx, "tmutil", "localsnapshot"); err != nil {
		return failResult(ActionSnapshot, err.Error()),
			fmt.Errorf("snapshot handler: tmutil snapshot: %w", err)
	}
	return okResult(ActionSnapshot, "APFS local snapshot created via tmutil"), nil
}

func (h *SnapshotHandler) restoreDarwin(ctx context.Context, name string) (*StepResult, error) {
	// APFS restore requires mounting the snapshot and copying, or a reboot-based
	// restore. This is the safest automated approach.
	return failResult(ActionSnapshot, "APFS snapshot restore requires manual intervention"),
		fmt.Errorf("snapshot handler: automated APFS restore not supported")
}

func (h *SnapshotHandler) deleteDarwin(ctx context.Context, name string) error {
	return runCmd(ctx, "tmutil", "deletelocalsnapshots", name)
}

// ---------------------------------------------------------------------------
// Windows — Volume Shadow Copy (VSS)
// ---------------------------------------------------------------------------

func (h *SnapshotHandler) createWindows(ctx context.Context, name string) (*StepResult, error) {
	out, err := exec.CommandContext(ctx, "vssadmin", "create", "shadow", "/for=C:").CombinedOutput()
	if err != nil {
		return failResult(ActionSnapshot, err.Error()),
			fmt.Errorf("snapshot handler: vssadmin create: %w (%s)", err, string(out))
	}
	return okResult(ActionSnapshot, fmt.Sprintf("VSS shadow copy created: %s", strings.TrimSpace(string(out)))), nil
}

func (h *SnapshotHandler) restoreWindows(ctx context.Context, name string) (*StepResult, error) {
	return failResult(ActionSnapshot, "VSS restore requires manual intervention"),
		fmt.Errorf("snapshot handler: automated VSS restore not supported")
}

func (h *SnapshotHandler) deleteWindows(ctx context.Context, name string) error {
	return runCmd(ctx, "vssadmin", "delete", "shadows", "/shadow="+name, "/quiet")
}
