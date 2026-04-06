package forensics

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// CustodyEntry records a single custody event in the evidence chain.
type CustodyEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"` // collected | transferred | analyzed | stored
	AgentID     string    `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	ArtifactID  string    `json:"artifact_id"`
	SHA256      string    `json:"sha256"`
	HMAC        string    `json:"hmac"`
	Description string    `json:"description"`
}

// ChainOfCustody maintains a cryptographic chain of HMAC-signed custody
// records. Each entry's HMAC incorporates the previous entry's HMAC,
// creating a tamper-evident chain. Verification detects any alteration.
type ChainOfCustody struct {
	mu      sync.Mutex
	entries []CustodyEntry
	hmacKey []byte
}

// NewChainOfCustody creates a new chain using the given HMAC key.
// The key should be at least 32 bytes for HMAC-SHA256 security.
func NewChainOfCustody(hmacKey []byte) *ChainOfCustody {
	return &ChainOfCustody{
		hmacKey: hmacKey,
	}
}

// AddEntry appends a custody record to the chain. The HMAC is computed
// over the entry fields concatenated with the previous entry's HMAC,
// creating an unbreakable chain.
func (cc *ChainOfCustody) AddEntry(action, agentID, hostname, artifactID, sha256Hash, description string) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	var prevHMAC string
	if len(cc.entries) > 0 {
		prevHMAC = cc.entries[len(cc.entries)-1].HMAC
	}

	entry := CustodyEntry{
		Timestamp:   time.Now().UTC(),
		Action:      action,
		AgentID:     agentID,
		Hostname:    hostname,
		ArtifactID:  artifactID,
		SHA256:      sha256Hash,
		Description: description,
	}
	entry.HMAC = cc.computeHMAC(entry, prevHMAC)
	cc.entries = append(cc.entries, entry)
	return nil
}

// Verify walks the entire chain and re-computes every HMAC. It returns
// an error at the first entry whose HMAC does not match.
func (cc *ChainOfCustody) Verify() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	prevHMAC := ""
	for i, entry := range cc.entries {
		expected := cc.computeHMAC(entry, prevHMAC)
		if entry.HMAC != expected {
			return fmt.Errorf("chain_of_custody: integrity violation at entry %d "+
				"(artifact=%s, action=%s)", i, entry.ArtifactID, entry.Action)
		}
		prevHMAC = entry.HMAC
	}
	return nil
}

// Export serializes the chain as a signed JSON document. The outer HMAC
// covers the entire JSON payload so tampering is detectable even if the
// chain is extracted from its storage context.
func (cc *ChainOfCustody) Export() ([]byte, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	type signedExport struct {
		Entries   []CustodyEntry `json:"entries"`
		ExportTS time.Time      `json:"export_timestamp"`
		HMAC     string         `json:"export_hmac"`
	}

	payload := signedExport{
		Entries:   cc.entries,
		ExportTS:  time.Now().UTC(),
	}

	entriesJSON, err := json.Marshal(payload.Entries)
	if err != nil {
		return nil, fmt.Errorf("chain_of_custody: marshal entries: %w", err)
	}

	mac := hmac.New(sha256.New, cc.hmacKey)
	mac.Write(entriesJSON)
	mac.Write([]byte(payload.ExportTS.Format(time.RFC3339Nano)))
	payload.HMAC = hex.EncodeToString(mac.Sum(nil))

	return json.MarshalIndent(payload, "", "  ")
}

// Len returns the number of entries in the chain.
func (cc *ChainOfCustody) Len() int {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return len(cc.entries)
}

// computeHMAC produces the HMAC-SHA256 for an entry, incorporating the
// previous entry's HMAC to form the chain link.
func (cc *ChainOfCustody) computeHMAC(entry CustodyEntry, prevHMAC string) string {
	mac := hmac.New(sha256.New, cc.hmacKey)
	mac.Write([]byte(entry.Timestamp.Format(time.RFC3339Nano)))
	mac.Write([]byte(entry.Action))
	mac.Write([]byte(entry.AgentID))
	mac.Write([]byte(entry.Hostname))
	mac.Write([]byte(entry.ArtifactID))
	mac.Write([]byte(entry.SHA256))
	mac.Write([]byte(entry.Description))
	mac.Write([]byte(prevHMAC))
	return hex.EncodeToString(mac.Sum(nil))
}

// ForFile is a convenience that computes the SHA-256 of a file and
// records a custody entry for it.
func (cc *ChainOfCustody) ForFile(path, action, agentID, description string) error {
	hostname, _ := os.Hostname()
	hash, err := sha256File(path)
	if err != nil {
		return fmt.Errorf("chain_of_custody: hash %s: %w", path, err)
	}
	return cc.AddEntry(action, agentID, hostname, path, hash, description)
}
