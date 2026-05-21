package collector

import (
	"encoding/json"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

// OCSFEnvelopeFromEvent returns the canonical OCSF map for a schema event or flat map.
func OCSFEnvelopeFromEvent(event interface{}, product ocsf.Product) map[string]any {
	if event == nil {
		return nil
	}
	switch v := event.(type) {
	case map[string]interface{}:
		return ocsf.OCSFEnvelopeFromFlat(v)
	}
	if base := baseEventFrom(event); base != nil && len(base.OCSF) > 0 {
		return base.OCSF
	}
	switch ev := event.(type) {
	case *schema.ProcessEvent:
		return ocsf.EnvelopeToMap(ocsfFromProcess(ev, product))
	case schema.ProcessEvent:
		return ocsf.EnvelopeToMap(ocsfFromProcess(&ev, product))
	case *schema.FileEvent:
		return ocsf.EnvelopeToMap(ocsfFromFile(ev, product))
	case schema.FileEvent:
		return ocsf.EnvelopeToMap(ocsfFromFile(&ev, product))
	case *schema.NetworkEvent:
		return ocsf.EnvelopeToMap(ocsfFromNetwork(ev, product))
	case schema.NetworkEvent:
		return ocsf.EnvelopeToMap(ocsfFromNetwork(&ev, product))
	case *schema.AuthEvent:
		return ocsf.EnvelopeToMap(ocsfFromAuth(ev, product))
	case schema.AuthEvent:
		return ocsf.EnvelopeToMap(ocsfFromAuth(&ev, product))
	case *schema.ForkEvent:
		return ocsf.EnvelopeToMap(ocsfFromFork(ev, product))
	case schema.ForkEvent:
		return ocsf.EnvelopeToMap(ocsfFromFork(&ev, product))
	case *schema.RegistryEvent:
		return ocsf.EnvelopeToMap(ocsfFromRegistry(ev, product))
	case schema.RegistryEvent:
		return ocsf.EnvelopeToMap(ocsfFromRegistry(&ev, product))
	case *schema.ProcessInjectionEvent:
		return ocsf.EnvelopeToMap(ocsfFromInjection(ev, product))
	case schema.ProcessInjectionEvent:
		return ocsf.EnvelopeToMap(ocsfFromInjection(&ev, product))
	case *schema.ComplianceFindingEvent:
		return ocsf.EnvelopeToMap(ocsfFromComplianceFinding(ev, product))
	case schema.ComplianceFindingEvent:
		return ocsf.EnvelopeToMap(ocsfFromComplianceFinding(&ev, product))
	case *schema.ComplianceScanSummaryEvent:
		return ocsf.EnvelopeToMap(ocsfFromComplianceScan(ev, product))
	case schema.ComplianceScanSummaryEvent:
		return ocsf.EnvelopeToMap(ocsfFromComplianceScan(&ev, product))
	case *schema.PrivilegeEvent:
		return ocsf.EnvelopeToMap(ocsfFromPrivilege(ev, product))
	case schema.PrivilegeEvent:
		return ocsf.EnvelopeToMap(ocsfFromPrivilege(&ev, product))
	case *schema.TaskEvent:
		return ocsf.EnvelopeToMap(ocsf.FromScheduledJob(ocsf.ScheduledJobInput{
			EndpointID: ev.EndpointID, Hostname: ev.Hostname, OS: ev.OS,
			Timestamp: ev.Timestamp.UnixMilli(), TaskName: ev.TaskName,
			TaskContent: ev.TaskContent, Operation: ev.Operation, SubjectUser: ev.SubjectUser,
		}, product))
	case *schema.ServiceEvent:
		return ocsf.EnvelopeToMap(ocsf.FromService(ocsf.ServiceInput{
			EndpointID: ev.EndpointID, Hostname: ev.Hostname, OS: ev.OS,
			Timestamp: ev.Timestamp.UnixMilli(), ServiceName: ev.ServiceName,
			ImagePath: ev.ImagePath, ServiceType: ev.ServiceType, StartType: ev.StartType,
			AccountName: ev.AccountName,
		}, product))
	case *schema.CredentialAccessEvent:
		return ocsf.EnvelopeToMap(ocsf.FromCredentialAccess(ocsf.CredentialInput{
			EndpointID: ev.EndpointID, Hostname: ev.Hostname, OS: ev.OS,
			Timestamp: ev.Timestamp.UnixMilli(), Technique: ev.Technique,
			SourcePID: int(ev.SourcePID), SourceProcess: ev.SourceProcess,
			TargetPath: ev.TargetPath, AccessMask: ev.AccessMask, Severity: ev.Severity,
		}, product))
	case *schema.MemoryEvent:
		return ocsf.EnvelopeToMap(ocsf.FromMemory(ocsf.MemoryInput{
			EndpointID: ev.EndpointID, Hostname: ev.Hostname, OS: ev.OS,
			Timestamp: ev.Timestamp.UnixMilli(), Operation: ev.Operation,
			TargetPID: int(ev.TargetPID), TargetProcess: ev.TargetProcess,
			Address: ev.Address, Size: ev.Size, Protect: ev.Protect,
		}, product))
	case *schema.TamperEvent:
		return ocsf.EnvelopeToMap(ocsf.FromTamper(ocsf.TamperInput{
			EndpointID: ev.EndpointID, Hostname: ev.Hostname, OS: ev.OS,
			Timestamp: ev.Timestamp.UnixMilli(), Component: ev.Component,
			ProgramID: ev.ProgramID, Message: ev.Message,
		}, product))
	case *schema.PersistenceEvent:
		return ocsf.EnvelopeToMap(ocsf.FromPersistence(ocsf.PersistenceInput{
			EndpointID: ev.EndpointID, Hostname: ev.Hostname, OS: ev.OS,
			Timestamp: ev.Timestamp.UnixMilli(), Technique: ev.Technique,
			ExecutablePath: ev.ExecutablePath, ItemType: ev.ItemType,
			IsLegacy: ev.IsLegacy, IsManaged: ev.IsManaged,
			PID: int(ev.PID), ProcessPath: ev.ProcessPath,
		}, product))
	}
	data, err := json.Marshal(event)
	if err != nil {
		return nil
	}
	var flat map[string]interface{}
	if err := json.Unmarshal(data, &flat); err != nil {
		return nil
	}
	return ocsf.OCSFEnvelopeFromFlat(flat)
}

func baseEventFrom(event interface{}) *schema.BaseEvent {
	switch ev := event.(type) {
	case *schema.ProcessEvent:
		return &ev.BaseEvent
	case schema.ProcessEvent:
		return &ev.BaseEvent
	case *schema.FileEvent:
		return &ev.BaseEvent
	case schema.FileEvent:
		return &ev.BaseEvent
	case *schema.NetworkEvent:
		return &ev.BaseEvent
	case schema.NetworkEvent:
		return &ev.BaseEvent
	case *schema.AuthEvent:
		return &ev.BaseEvent
	case schema.AuthEvent:
		return &ev.BaseEvent
	case *schema.ForkEvent:
		return &ev.BaseEvent
	case schema.ForkEvent:
		return &ev.BaseEvent
	case *schema.RegistryEvent:
		return &ev.BaseEvent
	case schema.RegistryEvent:
		return &ev.BaseEvent
	case *schema.ProcessInjectionEvent:
		return &ev.BaseEvent
	case schema.ProcessInjectionEvent:
		return &ev.BaseEvent
	case *schema.ComplianceFindingEvent:
		return &ev.BaseEvent
	case schema.ComplianceFindingEvent:
		return &ev.BaseEvent
	case *schema.ComplianceScanSummaryEvent:
		return &ev.BaseEvent
	case schema.ComplianceScanSummaryEvent:
		return &ev.BaseEvent
	case *schema.PrivilegeEvent:
		return &ev.BaseEvent
	case schema.PrivilegeEvent:
		return &ev.BaseEvent
	default:
		return nil
	}
}
