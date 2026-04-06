package playbooks

import (
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/pkg/events"
)

// NewDataExfiltrationPlaybook returns an 8-step playbook for data exfiltration
// incidents (e.g., large uploads, DNS tunnelling, staging to cloud storage).
//
// Sequence:
//  1. Network isolate host (cut exfil channel immediately)
//  2. Suspend the exfiltrating process
//  3. Capture network forensics (pcap, connections, DNS cache)
//  4. Memory dump (capture buffered data, encryption keys)
//  5. Kill the process tree
//  6. Quarantine the exfiltration tool/script
//  7. Collect full forensic evidence package
//  8. Alert SOC with data exposure assessment
func NewDataExfiltrationPlaybook() *BasePlaybook {
	return &BasePlaybook{
		PlaybookName: "data_exfiltration_response",
		PlaybookDesc: "8-step automated response to data exfiltration: sever network, preserve evidence, and assess exposure.",
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
				Name:     "network_forensics",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":      ExtractPID(alert),
						"alert_id": alert.ID,
						"operator": "playbook:data_exfil:network_capture",
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
				Name:     "quarantine_tool",
				Action:   response.ActionQuarantineFile,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"path":     ExtractFilePath(alert),
						"reason":   "data exfiltration tool quarantine",
						"alert_id": alert.ID,
						"operator": "playbook:data_exfil",
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
						"operator": "playbook:data_exfil:full_forensics",
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
						"operator": "playbook:data_exfil:soc_exposure_report",
					}
				},
			},
		},
	}
}
