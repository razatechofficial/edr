package ocsf

import (
	"fmt"
	"strings"
)

func classNameForEventType(t string) string {
	switch t {
	case "process":
		return ClassProcessActivity
	case "file", "file_access":
		return ClassFileActivity
	case "network":
		return ClassNetworkActivity
	case "dns":
		return ClassDNSActivity
	case "auth", "authentication":
		return ClassAuthentication
	case "fork":
		return ClassProcessActivity
	case "registry":
		return ClassRegistryKeyActivity
	case "injection":
		return ClassProcessActivity
	case "compliance", "compliance_finding":
		return ClassSecurityFinding
	case "compliance_scan":
		return ClassSecurityFinding
	case "privilege":
		return ClassProcessActivity
	case "task", "scheduled_job":
		return ClassScheduledJobActivity
	case "service":
		return ClassWindowsServiceActivity
	case "credential", "credential_access":
		return ClassProcessActivity
	case "container":
		return ClassProcessActivity
	case "security_policy", "tamper", "persistence", "gatekeeper", "gatekeeper_bypass", "dropped_events", "ti_status", "feature_status":
		return ClassSecurityFinding
	case "privacy":
		return ClassProcessActivity
	default:
		return ""
	}
}

func classUIDForEventType(t string) int {
	switch t {
	case "process":
		return ClassUIDProcessActivity
	case "file", "file_access":
		return ClassUIDFileActivity
	case "network":
		return ClassUIDNetworkActivity
	case "dns":
		return ClassUIDDNSActivity
	case "task", "scheduled_job":
		return ClassUIDScheduledJobActivity
	case "service":
		return ClassUIDWindowsServiceActivity
	case "auth", "authentication":
		return ClassUIDAuthentication
	case "fork", "injection":
		return ClassUIDProcessActivity
	case "registry":
		return ClassUIDRegistryKeyActivity
	case "compliance", "compliance_finding", "compliance_scan":
		return ClassUIDSecurityFinding
	case "privilege":
		return ClassUIDProcessActivity
	case "credential", "credential_access", "container", "privacy":
		return ClassUIDProcessActivity
	case "security_policy", "tamper", "persistence", "gatekeeper", "gatekeeper_bypass", "dropped_events", "ti_status", "feature_status":
		return ClassUIDSecurityFinding
	default:
		return 0
	}
}

func setIfAbsent(m map[string]interface{}, key string, val interface{}) {
	if val == nil {
		return
	}
	if s, ok := val.(string); ok && s == "" {
		return
	}
	if _, exists := m[key]; !exists {
		m[key] = val
	}
}

func stringField(m map[string]interface{}, keys ...string) string {
	for _, want := range keys {
		for k, v := range m {
			if strings.EqualFold(k, want) {
				return strings.TrimSpace(fmt.Sprint(v))
			}
		}
	}
	return ""
}

func intField(m map[string]interface{}, keys ...string) int {
	s := stringField(m, keys...)
	if s == "" {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

// MergeFlatSchemaFields copies non-OCSF schema keys into a detection map.
func MergeFlatSchemaFields(out, in map[string]interface{}) {
	mergeFlatSchemaFields(out, in)
}
