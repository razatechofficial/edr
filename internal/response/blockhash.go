package response

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// BlockHashHandler implements ActionHandler for blocking file execution by
// SHA-256 hash using OS-level application control:
//   - Linux: fapolicyd rules or extended attributes (security.edr.blocked)
//   - macOS: xattr quarantine flag (com.apple.quarantine)
//   - Windows: AppLocker hash rules via PowerShell
type BlockHashHandler struct {
	logger   *zap.Logger
	dbPath   string
	mu       sync.Mutex
	blocked  map[string]blockEntry
}

type blockEntry struct {
	Hash      string    `json:"hash"`
	Reason    string    `json:"reason"`
	AlertID   string    `json:"alert_id,omitempty"`
	BlockedAt time.Time `json:"blocked_at"`
}

// NewBlockHashHandler creates a handler backed by a JSON deny-list file.
func NewBlockHashHandler(logger *zap.Logger, dbPath string) *BlockHashHandler {
	if dbPath == "" {
		dbPath = "/var/lib/edr/blocked_hashes.json"
	}
	h := &BlockHashHandler{
		logger:  logger,
		dbPath:  dbPath,
		blocked: make(map[string]blockEntry),
	}
	h.load()
	return h
}

// Execute blocks the hash specified in params["hash"]. Optional: "reason",
// "alert_id", "path" (file to apply xattr on).
func (h *BlockHashHandler) Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error) {
	hash := stringParam(params, "hash")
	if hash == "" {
		return failResult(ActionBlockHash, "hash parameter required"),
			fmt.Errorf("block hash: missing hash param")
	}
	hash = strings.ToLower(hash)

	entry := blockEntry{
		Hash:      hash,
		Reason:    stringParam(params, "reason"),
		AlertID:   stringParam(params, "alert_id"),
		BlockedAt: time.Now().UTC(),
	}

	h.mu.Lock()
	h.blocked[hash] = entry
	h.mu.Unlock()

	if err := h.persist(); err != nil {
		h.logger.Error("failed to persist blocked hash db", zap.Error(err))
	}

	if err := h.applyOSBlock(ctx, hash, stringParam(params, "path")); err != nil {
		h.logger.Warn("OS-level block failed (deny-list still updated)", zap.Error(err))
	}

	return okResult(ActionBlockHash, fmt.Sprintf("hash %s blocked", hash[:16])), nil
}

// Rollback removes the hash from the deny-list.
func (h *BlockHashHandler) Rollback(_ context.Context, params map[string]interface{}) error {
	hash := strings.ToLower(stringParam(params, "hash"))
	if hash == "" {
		return fmt.Errorf("block hash rollback: missing hash param")
	}
	h.mu.Lock()
	delete(h.blocked, hash)
	h.mu.Unlock()
	return h.persist()
}

// IsBlocked checks whether a hash is in the deny-list.
func (h *BlockHashHandler) IsBlocked(hash string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.blocked[strings.ToLower(hash)]
	return ok
}

func (h *BlockHashHandler) load() {
	data, err := os.ReadFile(h.dbPath)
	if err != nil {
		return
	}
	var entries []blockEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	for _, e := range entries {
		h.blocked[e.Hash] = e
	}
}

func (h *BlockHashHandler) persist() error {
	h.mu.Lock()
	entries := make([]blockEntry, 0, len(h.blocked))
	for _, e := range h.blocked {
		entries = append(entries, e)
	}
	h.mu.Unlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.dbPath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(h.dbPath, data, 0o640)
}

func (h *BlockHashHandler) applyOSBlock(ctx context.Context, hash, filePath string) error {
	switch runtime.GOOS {
	case "linux":
		return h.blockLinux(ctx, hash, filePath)
	case "darwin":
		return h.blockDarwin(ctx, filePath)
	case "windows":
		return h.blockWindows(ctx, hash)
	default:
		return fmt.Errorf("block_hash: unsupported OS %s", runtime.GOOS)
	}
}

func (h *BlockHashHandler) blockLinux(_ context.Context, hash, filePath string) error {
	if filePath != "" {
		out, err := exec.Command("setfattr", "-n", "security.edr.blocked", "-v", hash, filePath).CombinedOutput()
		if err != nil {
			h.logger.Warn("setfattr failed, file may still run", zap.String("path", filePath), zap.Error(err))
		} else {
			h.logger.Info("xattr block applied", zap.String("path", filePath), zap.String("output", strings.TrimSpace(string(out))))
			return nil
		}
	}

	rule := fmt.Sprintf("deny_audit perm=execute sha256hash=%s : all", hash)
	rulePath := fmt.Sprintf("/etc/fapolicyd/rules.d/edr_block_%s.rules", hash[:12])
	if err := os.WriteFile(rulePath, []byte(rule+"\n"), 0o644); err != nil {
		return fmt.Errorf("fapolicyd rule write: %w", err)
	}
	_, _ = exec.Command("fapolicyctl", "reload").CombinedOutput()
	return nil
}

func (h *BlockHashHandler) blockDarwin(_ context.Context, filePath string) error {
	if filePath == "" {
		return fmt.Errorf("macOS block requires file path")
	}
	out, err := exec.Command("xattr", "-w", "com.apple.quarantine", "0083;EDR;blocked", filePath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("xattr quarantine: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (h *BlockHashHandler) blockWindows(ctx context.Context, hash string) error {
	ps := fmt.Sprintf(
		`New-AppLockerPolicy -RuleType Hash -Deny -FileHash "%s" | Set-AppLockerPolicy -Merge`,
		hash,
	)
	out, err := exec.CommandContext(ctx, "powershell", "-Command", ps).CombinedOutput()
	if err != nil {
		return fmt.Errorf("AppLocker block: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
