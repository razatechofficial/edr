package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

const (
	inventorySnapshotFile = "inventory_snapshot.json"
	inventoryHashFile     = "inventory_snapshot.sha256"
)

// persistInventorySnapshot writes a canonical JSON snapshot of summary to dataDir and
// returns (sha256Hex, changed, error). changed is true when hash differs from previous run on disk.
func persistInventorySnapshot(dataDir string, summary map[string]any) (sha256Hex string, changed bool, snapPath string, err error) {
	if dataDir == "" {
		return "", false, "", nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", false, "", err
	}
	canonical, err := canonicalJSONMap(summary)
	if err != nil {
		return "", false, "", err
	}
	h := sha256.Sum256(canonical)
	sha256Hex = hex.EncodeToString(h[:])

	prevPath := filepath.Join(dataDir, inventoryHashFile)
	prevHash, _ := os.ReadFile(prevPath)
	changed = len(prevHash) == 0 || string(prevHash) != sha256Hex

	snapPath = filepath.Join(dataDir, inventorySnapshotFile)
	if err := os.WriteFile(snapPath, canonical, 0o644); err != nil {
		return "", false, snapPath, err
	}
	if err := os.WriteFile(prevPath, []byte(sha256Hex), 0o644); err != nil {
		return sha256Hex, changed, snapPath, err
	}
	return sha256Hex, changed, snapPath, nil
}

func canonicalJSONMap(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]any, len(keys))
	for _, k := range keys {
		ordered[k] = m[k]
	}
	return json.MarshalIndent(ordered, "", "  ")
}
