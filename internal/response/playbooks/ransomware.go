package playbooks

import (
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/pkg/events"
)

// NewRansomwarePlaybook returns a 12-step playbook for ransomware incidents.
//
// Sequence:
//  1. Suspend offending process (halt encryption immediately)
//  2. Block file writes for the process (via quarantine of binary)
//  3. Memory dump (capture encryption keys in memory)
//  4. System snapshot (preserve current state for recovery)
//  5. Kill the process tree
//  6. Network isolate the host (prevent lateral spread)
//  7. Scan for additional malicious artifacts
//  8. Quarantine identified payloads
//  9. Collect forensic evidence
//  10. Generate incident report
//  11. Alert SOC
//  12. Await analyst decision (no-op sentinel step)
func NewRansomwarePlaybook() *BasePlaybook {
	return &BasePlaybook{
		PlaybookName: "ransomware_response",
		PlaybookDesc: "12-step automated response to ransomware detection: suspend, contain, preserve evidence, and isolate host.",
		PlaybookSteps: []Step{
			{
				Name:     "suspend_process",
				Action:   response.OpSuspendProcess,
				Required: true,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":          ExtractPID(alert),
						"process_name": ExtractProcessName(alert),
						"mode":         "suspend",
					}
				},
			},
			{
				Name:     "block_writes_quarantine_binary",
				Action:   response.OpQuarantineFile,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"path":     ExtractFilePath(alert),
						"reason":   "ransomware binary quarantine",
						"alert_id": alert.ID,
						"operator": "playbook:ransomware",
					}
				},
			},
			{
				Name:     "memory_dump",
				Action:   response.OpMemoryDump,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":          ExtractPID(alert),
						"process_name": ExtractProcessName(alert),
						"alert_id":     alert.ID,
					}
				},
			},
			{
				Name:     "system_snapshot",
				Action:   response.OpSnapshot,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"mode": "create",
					}
				},
			},
			{
				Name:     "kill_process_tree",
				Action:   response.OpKillProcess,
				Required: true,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":          ExtractPID(alert),
						"process_name": ExtractProcessName(alert),
						"mode":         "kill",
						"tree":         true,
						"requires_approval": true,
					}
				},
			},
			{
				Name:     "network_isolate",
				Action:   response.OpNetworkIsolate,
				Required: true,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"action":            "isolate",
						"requires_approval": true,
					}
				},
			},
			{
				Name:     "scan_artifacts",
				Action:   response.OpCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":      ExtractPID(alert),
						"alert_id": alert.ID,
						"operator": "playbook:ransomware:scan",
					}
				},
			},
			{
				Name:     "quarantine_payloads",
				Action:   response.OpQuarantineFile,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"path":     ExtractFilePath(alert),
						"reason":   "ransomware payload quarantine",
						"alert_id": alert.ID,
						"operator": "playbook:ransomware",
					}
				},
			},
			{
				Name:     "collect_forensics",
				Action:   response.OpCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":      ExtractPID(alert),
						"alert_id": alert.ID,
						"operator": "playbook:ransomware:forensics",
					}
				},
			},
			{
				Name:     "block_hash",
				Action:   response.OpBlockHash,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"hash":     ExtractHash(alert),
						"alert_id": alert.ID,
					}
				},
			},
			{
				Name:     "alert_soc",
				Action:   response.OpCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"alert_id": alert.ID,
						"operator": "playbook:ransomware:soc_notification",
					}
				},
			},
			{
				Name:     "await_analyst",
				Action:   response.OpCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"alert_id": alert.ID,
						"operator": "playbook:ransomware:await_decision",
					}
				},
			},
		},
	}
}
