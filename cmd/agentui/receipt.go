package main

import (
	"regexp"
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
	fields := parseEnrollReceipt(out)
	storage := fields["secure_storage"]
	switch strings.ToLower(storage) {
	case "keychain":
		storage = "macOS Keychain"
	case "dpapi":
		storage = "Windows DPAPI"
	case "file", "":
		storage = storageLabel()
	}
	valid := firstNonEmpty(fields["cert_not_after"], st.CertExpiry)
	if t, err := time.Parse(time.RFC3339, valid); err == nil {
		valid = t.UTC().Format("02 Jan 2006, 15:04 UTC")
	}
	if valid == "" {
		valid = "—"
	}
	issued := "Averox RA"
	return identityReceipt{
		DeviceID:   dash(firstNonEmpty(fields["agent_id"], st.AgentID)),
		MachineID:  dash(firstNonEmpty(fields["machine_id"], st.MachineID)),
		IssuedBy:   issued,
		ValidUntil: valid,
		Storage:    storage,
		EnrolledAt: time.Now().UTC().Format("02 Jan 2006, 15:04 UTC"),
	}
}

var enrollKV = regexp.MustCompile(`(agent_id|machine_id|secure_storage|cert_not_after)=(\S+)`)

func parseEnrollReceipt(s string) map[string]string {
	s = strings.ReplaceAll(s, "\r", "\n")
	out := map[string]string{}
	for _, m := range enrollKV.FindAllStringSubmatch(s, -1) {
		out[m[1]] = strings.Trim(m[2], `[]"`)
	}
	return out
}

func enrollLooksSuccessful(out string, err error, st operatorStatus) bool {
	if st.Enrolled && strings.TrimSpace(st.AgentID) != "" {
		return true
	}
	if parseEnrollReceipt(out)["agent_id"] != "" {
		return true
	}
	return err == nil && strings.TrimSpace(st.AgentID) != ""
}

func (c *console) applyEnrolled(st operatorStatus, r identityReceipt) {
	st.Enrolled = true
	if id := undash(r.DeviceID); id != "" {
		st.AgentID = id
	}
	if id := undash(r.MachineID); id != "" {
		st.MachineID = id
	}
	if r.ValidUntil != "" && r.ValidUntil != "—" {
		if t, err := time.Parse("02 Jan 2006, 15:04 UTC", r.ValidUntil); err == nil {
			st.CertExpiry = t.Format(time.RFC3339)
		}
	}
	c.last = st
}

// mergeEnrollment keeps a successful in-session enroll when user-level
// `edrctl ui` cannot read root-owned agent.yaml / enrollment.json.
func mergeEnrollment(st, session operatorStatus) operatorStatus {
	if st.Enrolled && strings.TrimSpace(st.AgentID) != "" {
		return st
	}
	if session.Enrolled || strings.TrimSpace(session.AgentID) != "" {
		st.Enrolled = true
		st.AgentID = firstNonEmpty(st.AgentID, session.AgentID)
		st.MachineID = firstNonEmpty(st.MachineID, session.MachineID)
		st.CertExpiry = firstNonEmpty(st.CertExpiry, session.CertExpiry)
		st.Ingest = firstNonEmpty(st.Ingest, session.Ingest)
	}
	return st
}

func undash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "—" {
		return ""
	}
	return s
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
	switch {
	case isDarwin():
		return "Store cert in macOS Keychain (encrypted)"
	case isWindows():
		return "Store cert in Windows Certificate Store (DPAPI)"
	default:
		return "Store cert in sealed local keystore"
	}
}

func identityWaiting() string {
	switch {
	case isDarwin(), isWindows():
		return "Waiting for administrator approval…"
	default:
		return "Starting enrollment…"
	}
}

func identityDoing(i int) string {
	doings := []string{
		"Validating the enrollment token…",
		"Generating the device identity key pair…",
		"Building the certificate signing request…",
		"Signing the CSR with the private PKI…",
		"Receiving the signed certificate and CA chain…",
		"Storing the certificate in the OS keystore…",
		"Connecting to ingest with the device certificate…",
	}
	if i < 0 || i >= len(doings) {
		return ""
	}
	return doings[i]
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
