package main

import (
	"strings"
	"time"
)

type identityReceipt struct {
	DeviceID   string
	MachineID  string
	IssuedBy   string
	ValidUntil string
	Storage    string
	EnrolledAt string
}

func receiptFromEnroll(out string, st operatorStatus) identityReceipt {
	fields := parseEqualsFields(out)
	storage := fields["secure_storage"]
	switch strings.ToLower(storage) {
	case "keychain":
		storage = "macOS Keychain"
	case "dpapi":
		storage = "Windows DPAPI"
	case "file", "":
		storage = storageLabel()
	}
	valid := fields["cert_not_after"]
	if valid == "" {
		valid = st.CertExpiry
	}
	if t, err := time.Parse(time.RFC3339, valid); err == nil {
		valid = t.UTC().Format("02 Jan 2006, 15:04 UTC")
	}
	if valid == "" {
		valid = "—"
	}
	issued := "Averox RA"
	return identityReceipt{
		DeviceID:   dash(firstNonEmpty(st.AgentID, fields["agent_id"])),
		MachineID:  dash(firstNonEmpty(st.MachineID, fields["machine_id"])),
		IssuedBy:   issued,
		ValidUntil: valid,
		Storage:    storage,
		EnrolledAt: time.Now().UTC().Format("02 Jan 2006, 15:04 UTC"),
	}
}

func parseEqualsFields(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Fields(s) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "[]")
		out[k] = v
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var identityStepTitles = []string{
	"Validate enrollment token with XDR gateway",
	"Generate ECDSA P-256 key pair",
	"Build certificate signing request (CSR)",
	"Signing CSR with private PKI (Averox RA)",
	"Receive signed device certificate + CA chain",
	"Store cert in the OS keystore",
	"Connect to ingest service via mTLS",
}

func identityKeyTitle() string {
	switch {
	case isDarwin():
		return "Generate ECDSA P-256 key pair in Secure Enclave"
	case isWindows():
		return "Generate ECDSA P-256 key pair in TPM / platform CNG"
	default:
		return "Generate ECDSA P-256 key pair (sealed keystore)"
	}
}

func identityStoreTitle() string {
	return "Store cert in " + storageLabel()
}

func identityTitles() []string {
	t := append([]string(nil), identityStepTitles...)
	t[1] = identityKeyTitle()
	t[5] = identityStoreTitle()
	return t
}

var identityStepIDs = []string{"token", "key", "csr", "sign", "cert", "store", "ingest"}

func identityStepIndex(id string) int {
	id = strings.TrimSpace(id)
	if id == "done" {
		return len(identityStepIDs) - 1
	}
	for i, s := range identityStepIDs {
		if s == id {
			return i
		}
	}
	return -1
}
