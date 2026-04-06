package playbooks

import (
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/pkg/events"
)

// NewCredentialDumpPlaybook returns an 8-step playbook for credential theft /
// credential dumping incidents (e.g., Mimikatz, LSASS access, SAM extraction).
//
// Sequence:
//  1. Suspend the dumping process (preserve memory state)
//  2. Memory dump (capture credentials in transit)
//  3. Kill the process
//  4. Quarantine the dumping tool
//  5. Force password rotation for affected accounts
//  6. Block the tool hash across all endpoints
//  7. Collect forensic evidence
//  8. Alert SOC with credential exposure report
func NewCredentialDumpPlaybook() *BasePlaybook {
	return &BasePlaybook{
		PlaybookName: "credential_dump_response",
		PlaybookDesc: "8-step automated response to credential theft: suspend attacker, preserve evidence, rotate credentials, and contain.",
		PlaybookSteps: []Step{
			{
				Name:     "suspend_dumping_process",
				Action:   response.ActionSuspendProcess,
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
				Name:     "memory_dump",
				Action:   response.ActionMemoryDump,
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
				Name:     "kill_process",
				Action:   response.ActionKillProcess,
				Required: true,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":          ExtractPID(alert),
						"process_name": ExtractProcessName(alert),
						"mode":         "kill",
						"tree":         true,
					}
				},
			},
			{
				Name:     "quarantine_tool",
				Action:   response.ActionQuarantineFile,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"path":     ExtractFilePath(alert),
						"reason":   "credential dumping tool quarantine",
						"alert_id": alert.ID,
						"operator": "playbook:credential_dump",
					}
				},
			},
			{
				Name:     "force_password_rotation",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"alert_id": alert.ID,
						"operator": "playbook:credential_dump:password_rotation",
					}
				},
			},
			{
				Name:     "block_tool_hash",
				Action:   response.ActionBlockHash,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"hash":     ExtractHash(alert),
						"alert_id": alert.ID,
					}
				},
			},
			{
				Name:     "collect_forensics",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":      ExtractPID(alert),
						"alert_id": alert.ID,
						"operator": "playbook:credential_dump:forensics",
					}
				},
			},
			{
				Name:     "alert_soc",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"alert_id": alert.ID,
						"operator": "playbook:credential_dump:soc_alert",
					}
				},
			},
		},
	}
}
