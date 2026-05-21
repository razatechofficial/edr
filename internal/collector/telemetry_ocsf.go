package collector

import (
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

// OCSFProductVersion is set by the agent before forwarding telemetry (build/version label).
var OCSFProductVersion string

// EnsureTelemetryOCSF attaches an OCSF 1.3 envelope to schema events when absent.
func EnsureTelemetryOCSF(t *Telemetry) {
	if t == nil {
		return
	}
	product := ocsf.DefaultProduct(OCSFProductVersion)
	switch {
	case t.Process != nil:
		attachOCSF(&t.Process.BaseEvent, ocsfFromProcess(t.Process, product))
	case t.File != nil:
		attachOCSF(&t.File.BaseEvent, ocsfFromFile(t.File, product))
	case t.Network != nil:
		attachOCSF(&t.Network.BaseEvent, ocsfFromNetwork(t.Network, product))
	case t.Auth != nil:
		attachOCSF(&t.Auth.BaseEvent, ocsfFromAuth(t.Auth, product))
	case t.Fork != nil:
		attachOCSF(&t.Fork.BaseEvent, ocsfFromFork(t.Fork, product))
	case t.Registry != nil:
		attachOCSF(&t.Registry.BaseEvent, ocsfFromRegistry(t.Registry, product))
	case t.Injection != nil:
		attachOCSF(&t.Injection.BaseEvent, ocsfFromInjection(t.Injection, product))
	case t.Compliance != nil:
		attachOCSF(&t.Compliance.BaseEvent, ocsfFromComplianceFinding(t.Compliance, product))
	case t.ComplianceScan != nil:
		attachOCSF(&t.ComplianceScan.BaseEvent, ocsfFromComplianceScan(t.ComplianceScan, product))
	case t.Privilege != nil:
		attachOCSF(&t.Privilege.BaseEvent, ocsfFromPrivilege(t.Privilege, product))
	case t.Task != nil:
		ev := t.Task
		attachOCSF(&ev.BaseEvent, ocsf.FromScheduledJob(ocsf.ScheduledJobInput{
			EndpointID:  ev.EndpointID,
			Hostname:    ev.Hostname,
			OS:          ev.OS,
			Timestamp:   ev.Timestamp.UnixMilli(),
			TaskName:    ev.TaskName,
			TaskContent: ev.TaskContent,
			Operation:   ev.Operation,
			SubjectUser: ev.SubjectUser,
		}, product))
	case t.Service != nil:
		ev := t.Service
		attachOCSF(&ev.BaseEvent, ocsf.FromService(ocsf.ServiceInput{
			EndpointID:  ev.EndpointID,
			Hostname:    ev.Hostname,
			OS:          ev.OS,
			Timestamp:   ev.Timestamp.UnixMilli(),
			ServiceName: ev.ServiceName,
			ImagePath:   ev.ImagePath,
			ServiceType: ev.ServiceType,
			StartType:   ev.StartType,
			AccountName: ev.AccountName,
		}, product))
	case t.Credential != nil:
		ev := t.Credential
		attachOCSF(&ev.BaseEvent, ocsf.FromCredentialAccess(ocsf.CredentialInput{
			EndpointID:    ev.EndpointID,
			Hostname:      ev.Hostname,
			OS:            ev.OS,
			Timestamp:     ev.Timestamp.UnixMilli(),
			Technique:     ev.Technique,
			SourcePID:     int(ev.SourcePID),
			SourceProcess: ev.SourceProcess,
			TargetPath:    ev.TargetPath,
			AccessMask:    ev.AccessMask,
			Severity:      ev.Severity,
		}, product))
	case t.Memory != nil:
		ev := t.Memory
		attachOCSF(&ev.BaseEvent, ocsf.FromMemory(ocsf.MemoryInput{
			EndpointID:    ev.EndpointID,
			Hostname:      ev.Hostname,
			OS:            ev.OS,
			Timestamp:     ev.Timestamp.UnixMilli(),
			Operation:     ev.Operation,
			TargetPID:     int(ev.TargetPID),
			TargetProcess: ev.TargetProcess,
			Address:       ev.Address,
			Size:          ev.Size,
			Protect:       ev.Protect,
		}, product))
	case t.Container != nil:
		ev := t.Container
		attachOCSF(&ev.BaseEvent, ocsf.FromContainer(ocsf.ContainerInput{
			EndpointID:  ev.EndpointID,
			Hostname:    ev.Hostname,
			OS:          ev.OS,
			Timestamp:   ev.Timestamp.UnixMilli(),
			Operation:   ev.Operation,
			PID:         ev.PID,
			ProcessName: ev.ProcessName,
			Path:        ev.Path,
			Mode:        ev.Mode,
		}, product))
	case t.SecPolicy != nil:
		ev := t.SecPolicy
		attachOCSF(&ev.BaseEvent, ocsf.FromSecPolicy(ocsf.SecPolicyInput{
			EndpointID: ev.EndpointID,
			Hostname:   ev.Hostname,
			OS:         ev.OS,
			Timestamp:  ev.Timestamp.UnixMilli(),
			Operation:  ev.Operation,
			PID:        ev.PID,
			Flags:      ev.Flags,
		}, product))
	case t.Tamper != nil:
		ev := t.Tamper
		attachOCSF(&ev.BaseEvent, ocsf.FromTamper(ocsf.TamperInput{
			EndpointID: ev.EndpointID,
			Hostname:   ev.Hostname,
			OS:         ev.OS,
			Timestamp:  ev.Timestamp.UnixMilli(),
			Component:  ev.Component,
			ProgramID:  ev.ProgramID,
			Message:    ev.Message,
		}, product))
	case t.Persistence != nil:
		ev := t.Persistence
		attachOCSF(&ev.BaseEvent, ocsf.FromPersistence(ocsf.PersistenceInput{
			EndpointID:     ev.EndpointID,
			Hostname:       ev.Hostname,
			OS:             ev.OS,
			Timestamp:      ev.Timestamp.UnixMilli(),
			Technique:      ev.Technique,
			ExecutablePath: ev.ExecutablePath,
			ItemType:       ev.ItemType,
			IsLegacy:       ev.IsLegacy,
			IsManaged:      ev.IsManaged,
			PID:            int(ev.PID),
			ProcessPath:    ev.ProcessPath,
		}, product))
	case t.Privacy != nil:
		ev := t.Privacy
		attachOCSF(&ev.BaseEvent, ocsf.FromPrivacy(ocsf.PrivacyInput{
			EndpointID:       ev.EndpointID,
			Hostname:         ev.Hostname,
			OS:               ev.OS,
			Timestamp:        ev.Timestamp.UnixMilli(),
			Operation:        ev.Operation,
			Service:          ev.Service,
			AuthValue:        ev.AuthValue,
			AuthReason:       ev.AuthReason,
			AccessingPID:     int(ev.AccessingPID),
			AccessingProcess: ev.AccessingProcess,
		}, product))
	case t.Gatekeeper != nil:
		ev := t.Gatekeeper
		attachOCSF(&ev.BaseEvent, ocsf.FromGatekeeper(ocsf.GatekeeperInput{
			EndpointID:    ev.EndpointID,
			Hostname:      ev.Hostname,
			OS:            ev.OS,
			Timestamp:     ev.Timestamp.UnixMilli(),
			FilePath:      ev.FilePath,
			PID:           int(ev.PID),
			ProcessPath:   ev.ProcessPath,
			SigningStatus: ev.SigningStatus,
		}, product))
	case t.Dropped != nil:
		ev := t.Dropped
		attachOCSF(&ev.BaseEvent, ocsf.FromDropped(ocsf.DroppedInput{
			EndpointID: ev.EndpointID,
			Hostname:   ev.Hostname,
			OS:         ev.OS,
			Timestamp:  ev.Timestamp.UnixMilli(),
			EventClass: ev.EventClass,
			GapSize:    ev.GapSize,
			LastSeq:    ev.LastSeq,
			CurrentSeq: ev.CurrentSeq,
		}, product))
	case t.TIStatus != nil:
		ev := t.TIStatus
		attachOCSF(&ev.BaseEvent, ocsf.FromTIStatus(ocsf.TIStatusInput{
			EndpointID: ev.EndpointID,
			Hostname:   ev.Hostname,
			OS:         ev.OS,
			Timestamp:  ev.Timestamp.UnixMilli(),
			Status:     ev.Status,
			Reason:     ev.Reason,
		}, product))
	case t.FeatureStatus != nil:
		ev := t.FeatureStatus
		attachOCSF(&ev.BaseEvent, ocsf.FromFeatureStatus(ocsf.FeatureStatusInput{
			EndpointID: ev.EndpointID,
			Hostname:   ev.Hostname,
			OS:         ev.OS,
			Timestamp:  ev.Timestamp.UnixMilli(),
			Features:   ev.Features,
			Degraded:   ev.Degraded,
		}, product))
	}
}

func attachOCSF(base *schema.BaseEvent, env ocsf.Envelope) {
	if base == nil || len(base.OCSF) > 0 {
		return
	}
	if m := ocsf.EnvelopeToMap(env); len(m) > 0 {
		base.OCSF = m
	}
}

func ocsfEnvelopeForTelemetry(t *Telemetry) map[string]any {
	if t == nil {
		return nil
	}
	EnsureTelemetryOCSF(t)
	switch {
	case t.Process != nil:
		return t.Process.OCSF
	case t.File != nil:
		return t.File.OCSF
	case t.Network != nil:
		return t.Network.OCSF
	case t.Auth != nil:
		return t.Auth.OCSF
	case t.Fork != nil:
		return t.Fork.OCSF
	case t.Registry != nil:
		return t.Registry.OCSF
	case t.Injection != nil:
		return t.Injection.OCSF
	case t.Compliance != nil:
		return t.Compliance.OCSF
	case t.ComplianceScan != nil:
		return t.ComplianceScan.OCSF
	case t.Privilege != nil:
		return t.Privilege.OCSF
	case t.Task != nil:
		return t.Task.OCSF
	case t.Service != nil:
		return t.Service.OCSF
	case t.Credential != nil:
		return t.Credential.OCSF
	case t.Memory != nil:
		return t.Memory.OCSF
	case t.Container != nil:
		return t.Container.OCSF
	case t.SecPolicy != nil:
		return t.SecPolicy.OCSF
	case t.Tamper != nil:
		return t.Tamper.OCSF
	case t.Persistence != nil:
		return t.Persistence.OCSF
	case t.Privacy != nil:
		return t.Privacy.OCSF
	case t.Gatekeeper != nil:
		return t.Gatekeeper.OCSF
	case t.Dropped != nil:
		return t.Dropped.OCSF
	case t.TIStatus != nil:
		return t.TIStatus.OCSF
	case t.FeatureStatus != nil:
		return t.FeatureStatus.OCSF
	default:
		return nil
	}
}

func ocsfFromProcess(ev *schema.ProcessEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromProcess(ocsf.ProcessInput{
		EndpointID:  ev.EndpointID,
		Hostname:    ev.Hostname,
		OS:          ev.OS,
		Timestamp:   ev.Timestamp,
		PID:         ev.PID,
		PPID:        ev.PPID,
		ProcessName: ev.ProcessName,
		ProcessPath: ev.ProcessPath,
		CommandLine: ev.CommandLine,
		User:        ev.User,
	}, product)
}

func ocsfFromFile(ev *schema.FileEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromFile(ocsf.FileInput{
		EndpointID: ev.EndpointID,
		Timestamp:  ev.Timestamp,
		Path:       ev.Path,
		Operation:  ev.Operation,
		ActorPID:   ev.ActorPID,
	}, product)
}

func ocsfFromNetwork(ev *schema.NetworkEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromNetwork(ocsf.NetworkInput{
		EndpointID: ev.EndpointID,
		Hostname:   ev.Hostname,
		OS:         ev.OS,
		Timestamp:  ev.Timestamp.UnixMilli(),
		PID:        ev.PID,
		Protocol:   ev.Protocol,
		SourceIP:   ev.SourceIP,
		SourcePort: ev.SourcePt,
		DestIP:     ev.DestIP,
		DestPort:   ev.DestPt,
		Domain:     ev.Domain,
		Transport:  ev.Transport,
	}, product)
}

func ocsfFromAuth(ev *schema.AuthEvent, product ocsf.Product) ocsf.Envelope {
	srcIP := ev.SourceIP
	if srcIP == "" {
		srcIP = ev.IpAddress
	}
	return ocsf.FromAuth(ocsf.AuthInput{
		EndpointID: ev.EndpointID,
		Hostname:   ev.Hostname,
		OS:         ev.OS,
		Timestamp:  ev.Timestamp.UnixMilli(),
		User:       ev.User,
		Outcome:    ev.Outcome,
		AuthType:   ev.AuthType,
		SourceIP:   srcIP,
		Success:    ev.Success,
		Message:    ev.Message,
		Subsystem:  ev.Subsystem,
	}, product)
}

func ocsfFromFork(ev *schema.ForkEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromFork(ocsf.ForkInput{
		EndpointID: ev.EndpointID,
		Hostname:   ev.Hostname,
		OS:         ev.OS,
		Timestamp:  ev.Timestamp.UnixMilli(),
		ParentPID:  ev.ParentPID,
		ChildPID:   ev.ChildPID,
		CloneFlags: ev.CloneFlags,
	}, product)
}

func ocsfFromRegistry(ev *schema.RegistryEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromRegistry(ocsf.RegistryInput{
		EndpointID: ev.EndpointID,
		Hostname:   ev.Hostname,
		OS:         ev.OS,
		Timestamp:  ev.Timestamp.UnixMilli(),
		KeyPath:    ev.KeyPath,
		ValueName:  ev.ValueName,
		Operation:  ev.Operation,
		ActorPID:   ev.ActorPID,
	}, product)
}

func ocsfFromInjection(ev *schema.ProcessInjectionEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromInjection(ocsf.InjectionInput{
		EndpointID:  ev.EndpointID,
		Hostname:    ev.Hostname,
		OS:          ev.OS,
		Timestamp:   ev.Timestamp.UnixMilli(),
		SourcePID:   ev.SourcePID,
		TargetPID:   ev.TargetPID,
		TargetImage: ev.TargetImage,
		Technique:   ev.Technique,
	}, product)
}

func ocsfFromComplianceFinding(ev *schema.ComplianceFindingEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromComplianceFinding(ocsf.ComplianceInput{
		EndpointID:  ev.EndpointID,
		Hostname:    ev.Hostname,
		OS:          ev.OS,
		PolicyID:    ev.PolicyID,
		PolicyName:  ev.PolicyName,
		CheckID:     ev.CheckID,
		Title:       ev.Title,
		Description: ev.Description,
		Remediation: ev.Remediation,
		Result:      ev.Result,
		Compliance:  ev.Compliance,
		MITRE:       ev.MITRE,
		Timestamp:   ev.Timestamp,
	}, product)
}

func ocsfFromComplianceScan(ev *schema.ComplianceScanSummaryEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromComplianceScan(ocsf.ComplianceScanInput{
		EndpointID:         ev.EndpointID,
		Hostname:           ev.Hostname,
		OS:                 ev.OS,
		Timestamp:          ev.Timestamp,
		Passed:             ev.Passed,
		Failed:             ev.Failed,
		Errors:             ev.Errors,
		Skipped:            ev.Skipped,
		PoliciesTotal:      ev.PoliciesTotal,
		PoliciesApplicable: ev.PoliciesApplicable,
		DurationMs:         ev.DurationMs,
	}, product)
}

func ocsfFromPrivilege(ev *schema.PrivilegeEvent, product ocsf.Product) ocsf.Envelope {
	return ocsf.FromPrivilege(ocsf.PrivilegeInput{
		EndpointID:  ev.EndpointID,
		Hostname:    ev.Hostname,
		OS:          ev.OS,
		Timestamp:   ev.Timestamp.UnixMilli(),
		PID:         int(ev.PID),
		PPID:        int(ev.PPID),
		Comm:        ev.Comm,
		Operation:   ev.Operation,
		SyscallNr:   ev.SyscallNr,
		NewUID:      ev.NewUID,
		NewGID:      ev.NewGID,
		EffectiveID: ev.EffectiveID,
		SavedID:     ev.SavedID,
		CallerUID:   ev.CallerUID,
	}, product)
}
