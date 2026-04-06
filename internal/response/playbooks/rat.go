package playbooks

import (
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/pkg/events"
)

// NewRATPlaybook returns a 10-step playbook for Remote Access Trojan incidents.
//
// Sequence:
//  1. Network-isolate the RAT process (block C2 communication)
//  2. Capture network traffic (pcap for 60s via forensics)
//  3. Memory dump (extract implant config, C2 addresses)
//  4. Extract IOCs from memory and network artifacts
//  5. Block C2 server IPs/domains
//  6. Kill the RAT process tree
//  7. Remove persistence mechanisms (scheduled tasks, startup entries)
//  8. YARA scan for related artifacts
//  9. IOC sweep across all endpoints (collect forensics)
//  10. Alert SOC with full IOC package
func NewRATPlaybook() *BasePlaybook {
	return &BasePlaybook{
		PlaybookName: "rat_response",
		PlaybookDesc: "10-step automated response to Remote Access Trojan detection: isolate C2, capture evidence, eradicate persistence.",
		PlaybookSteps: []Step{
			{
				Name:     "network_isolate_process",
				Action:   response.ActionNetworkIsolate,
				Required: true,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"action": "isolate",
					}
				},
			},
			{
				Name:     "capture_network_traffic",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":      ExtractPID(alert),
						"alert_id": alert.ID,
						"operator": "playbook:rat:pcap_60s",
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
				Name:     "extract_iocs",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":      ExtractPID(alert),
						"alert_id": alert.ID,
						"operator": "playbook:rat:ioc_extraction",
					}
				},
			},
			{
				Name:     "block_c2",
				Action:   response.ActionBlockHash,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"hash":     ExtractHash(alert),
						"c2_ip":    ExtractDestIP(alert),
						"alert_id": alert.ID,
					}
				},
			},
			{
				Name:     "kill_rat_process",
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
				Name:     "remove_persistence",
				Action:   response.ActionQuarantineFile,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"path":     ExtractFilePath(alert),
						"reason":   "RAT persistence mechanism removal",
						"alert_id": alert.ID,
						"operator": "playbook:rat",
					}
				},
			},
			{
				Name:     "yara_scan",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"pid":      ExtractPID(alert),
						"alert_id": alert.ID,
						"operator": "playbook:rat:yara_scan",
					}
				},
			},
			{
				Name:     "ioc_sweep",
				Action:   response.ActionCollectForensics,
				Required: false,
				Params: func(alert *events.Alert) map[string]interface{} {
					return map[string]interface{}{
						"alert_id": alert.ID,
						"operator": "playbook:rat:ioc_sweep",
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
						"operator": "playbook:rat:soc_alert",
					}
				},
			},
		},
	}
}
