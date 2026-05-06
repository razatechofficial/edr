package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	inventoryRecordsFile = "inventory_snapshot.records.json"
	inventoryDeltaFile   = "inventory_delta.json"
)

// InventoryRecordsRoot is a typed projection of L1 inventory for delta-friendly sync.
type InventoryRecordsRoot struct {
	Packages  []PackageRecord  `json:"packages,omitempty"`
	Services  []ServiceRecord  `json:"services,omitempty"`
	Listeners []ListenerRecord `json:"listeners,omitempty"`
	NICs      []NICRecord      `json:"nics,omitempty"`
}

type PackageRecord struct {
	ID       string `json:"id"`
	Checksum string `json:"checksum"`
	Name     string `json:"name"`
	Version  string `json:"version"`
}

type ServiceRecord struct {
	ID       string `json:"id"`
	Checksum string `json:"checksum"`
	Name     string `json:"name"`
	State    string `json:"state,omitempty"`
}

type ListenerRecord struct {
	ID       string `json:"id"`
	Checksum string `json:"checksum"`
	Proto    string `json:"proto,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Process  string `json:"process,omitempty"`
}

type NICRecord struct {
	ID       string `json:"id"`
	Checksum string `json:"checksum"`
	Name     string `json:"name"`
	State    string `json:"state,omitempty"`
}

// BuildInventoryRecordsFromSummary derives coarse records from the existing summary map (syscollector-style IDs).
func BuildInventoryRecordsFromSummary(m map[string]any) InventoryRecordsRoot {
	var r InventoryRecordsRoot
	if m == nil {
		return r
	}
	pk := PackageRecord{
		Name:    "packages_aggregate",
		Version: fmt.Sprint(m["package_count_est"]),
	}
	pk.ID = stableItemID("pkg", pk.Name, pk.Version)
	pk.Checksum = itemChecksum(pk.Name, pk.Version)
	r.Packages = append(r.Packages, pk)

	lis := ListenerRecord{
		Proto:   "aggregate",
		Addr:    fmt.Sprint(m["listening_socket_rows_est"]),
		Process: fmt.Sprint(m["listening_sockets_process_hint_rows_est"]),
	}
	lis.ID = stableItemID("listener", lis.Proto, lis.Addr, lis.Process)
	lis.Checksum = itemChecksum(lis.Proto, lis.Addr, lis.Process)
	r.Listeners = append(r.Listeners, lis)

	if rel, ok := m["os_release"].(string); ok && strings.TrimSpace(rel) != "" {
		n := NICRecord{Name: "os_release_digest", State: hashShort(rel)}
		n.ID = stableItemID("nic", n.Name, n.State)
		n.Checksum = itemChecksum(n.Name, n.State)
		r.NICs = append(r.NICs, n)
	}
	return r
}

func stableItemID(kind string, parts ...string) string {
	h := sha256.Sum256([]byte(kind + "|" + strings.Join(parts, "|")))
	return hex.EncodeToString(h[:12])
}

func itemChecksum(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x1e")))
	return hex.EncodeToString(h[:])
}

func hashShort(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// PersistInventoryRecordsAndMaybeDelta writes records JSON and, when emitDelta is true, inventory_delta.json.
func PersistInventoryRecordsAndMaybeDelta(dataDir string, cur InventoryRecordsRoot, emitDelta bool) (recordsPath string, deltaPath string, err error) {
	if dataDir == "" {
		return "", "", nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", "", err
	}
	b, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return "", "", err
	}
	recordsPath = filepath.Join(dataDir, inventoryRecordsFile)
	prev, _ := os.ReadFile(recordsPath)
	if err := os.WriteFile(recordsPath, b, 0o644); err != nil {
		return recordsPath, "", err
	}
	if !emitDelta {
		return recordsPath, "", nil
	}
	var prevSet InventoryRecordsRoot
	_ = json.Unmarshal(prev, &prevSet)
	delta := diffInventoryRecords(prevSet, cur)
	db, err := json.MarshalIndent(delta, "", "  ")
	if err != nil {
		return recordsPath, "", err
	}
	deltaPath = filepath.Join(dataDir, inventoryDeltaFile)
	if err := os.WriteFile(deltaPath, db, 0o644); err != nil {
		return recordsPath, deltaPath, err
	}
	return recordsPath, deltaPath, nil
}

// InventoryDelta is a coarse added/removed/changed set keyed by record id.
type InventoryDelta struct {
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
	Changed  []string `json:"changed,omitempty"`
	UpdatedAt string  `json:"updated_at,omitempty"`
}

func diffInventoryRecords(prev, cur InventoryRecordsRoot) InventoryDelta {
	prevIDs := recordIDMap(prev)
	curIDs := recordIDMap(cur)
	var d InventoryDelta
	for id := range curIDs {
		if _, ok := prevIDs[id]; !ok {
			d.Added = append(d.Added, id)
		} else if prevIDs[id] != curIDs[id] {
			d.Changed = append(d.Changed, id)
		}
	}
	for id := range prevIDs {
		if _, ok := curIDs[id]; !ok {
			d.Removed = append(d.Removed, id)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Changed)
	return d
}

func recordIDMap(r InventoryRecordsRoot) map[string]string {
	out := map[string]string{}
	for _, p := range r.Packages {
		out[p.ID] = p.Checksum
	}
	for _, s := range r.Services {
		out[s.ID] = s.Checksum
	}
	for _, l := range r.Listeners {
		out[l.ID] = l.Checksum
	}
	for _, n := range r.NICs {
		out[n.ID] = n.Checksum
	}
	return out
}
