package playbooks

import (
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/pkg/events"
)

// NewLateralMovementPlaybook returns a 9-step playbook for lateral movement
// incidents (e.g., PsExec, WMI abuse, RDP pivoting, SSH brute-force).
//
// Sequence:
//  1. Network isolate the compromised host
//  2. Suspend the lateral movement process
//  3. Memory dump (capture session tokens, tickets)
//  4. Collect network forensics (connections, ARP, DNS)
//  5. Kill the process tree
//  6. Block the tool/binary hash
//  7. Quarantine the lateral movement tool
//  8. System snapshot (preserve state before remediation)
//  9. Alert SOC with lateral movement scope assessment
func NewLateralMovementPlaybook() *BasePlaybook {
	return &BasePlaybook{
		PlaybookName: "lateral_movement_response",
		PlaybookDesc: "9-step automated response to lateral movement: isolate, capture evidence, block propagation, and alert.",
		PlaybookSteps: []Step{
			{
				Name:     "network_isolate",
				Action:   response.ActionNetworkIsolate,
				Required: true,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"action": "isolate",
					}
				},
			},
			{
				Name:     "suspend_process",
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
				Name:     "network_forensics",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":      ExtractPID(alert),
						"alert_id": alert.ID,
						"operator": "playbook:lateral_movement:network_forensics",
					}
				},
			},
			{
				Name:     "kill_process_tree",
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
				Name:     "block_hash",
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
				Name:     "quarantine_tool",
				Action:   response.ActionQuarantineFile,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"path":     ExtractFilePath(alert),
						"reason":   "lateral movement tool quarantine",
						"alert_id": alert.ID,
						"operator": "playbook:lateral_movement",
					}
				},
			},
			{
				Name:     "system_snapshot",
				Action:   response.ActionSnapshot,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"mode": "create",
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
						"operator": "playbook:lateral_movement:soc_alert_scope",
					}
				},
			},
		},
	}
}
