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
	case t.Task != nil:
		ev := t.Task
		attachSynthetic(&ev.BaseEvent, product, "task_scheduler", ev.TaskName, ev.Operation, 0, ev.SubjectUser, "task", nil)
	case t.Service != nil:
		ev := t.Service
		attachSynthetic(&ev.BaseEvent, product, "service_install", ev.ImagePath, ev.ServiceName, 0, ev.AccountName, "service", map[string]any{
			"service_type": ev.ServiceType,
			"start_type":   ev.StartType,
		})
	case t.Credential != nil:
		ev := t.Credential
		attachSynthetic(&ev.BaseEvent, product, "credential_access", ev.TargetPath, ev.Technique, int(ev.SourcePID), ev.SourceProcess, "credential_access", nil)
	case t.Memory != nil:
		ev := t.Memory
		attachSynthetic(&ev.BaseEvent, product, "memory_event", ev.TargetProcess, ev.Operation, int(ev.TargetPID), "", "memory", map[string]any{
			"address": ev.Address,
			"size":    ev.Size,
		})
	case t.Container != nil:
		ev := t.Container
		attachSynthetic(&ev.BaseEvent, product, ev.ProcessName, ev.Path, ev.Operation, ev.PID, "", "container", nil)
	case t.SecPolicy != nil:
		ev := t.SecPolicy
		attachSynthetic(&ev.BaseEvent, product, "security_policy", "", ev.Operation, ev.PID, "", "security_policy", nil)
	case t.Tamper != nil:
		ev := t.Tamper
		attachSynthetic(&ev.BaseEvent, product, "tamper", ev.Component, ev.Message, 0, "", "tamper", nil)
	case t.Persistence != nil:
		ev := t.Persistence
		attachSynthetic(&ev.BaseEvent, product, "persistence", ev.ExecutablePath, ev.Technique, int(ev.PID), "", "persistence", map[string]any{
			"item_type": ev.ItemType,
		})
	case t.Privacy != nil:
		ev := t.Privacy
		attachSynthetic(&ev.BaseEvent, product, "privacy", ev.AccessingProcess, ev.Operation, int(ev.AccessingPID), "", "privacy", map[string]any{
			"service": ev.Service,
		})
	case t.Gatekeeper != nil:
		ev := t.Gatekeeper
		attachSynthetic(&ev.BaseEvent, product, "gatekeeper_bypass", ev.FilePath, ev.ProcessPath, int(ev.PID), "", "gatekeeper", nil)
	case t.Dropped != nil:
		ev := t.Dropped
		attachSynthetic(&ev.BaseEvent, product, "dropped_events", "", ev.EventClass, 0, "", "dropped_events", map[string]any{
			"gap_size": ev.GapSize,
		})
	case t.TIStatus != nil:
		ev := t.TIStatus
		attachSynthetic(&ev.BaseEvent, product, "ti_status", "", ev.Status+":"+ev.Reason, 0, "", "ti_status", nil)
	case t.FeatureStatus != nil:
		ev := t.FeatureStatus
		attachSynthetic(&ev.BaseEvent, product, "feature_status", "", "feature_coverage", 0, "", "feature_status", nil)
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

func attachSynthetic(base *schema.BaseEvent, product ocsf.Product, name, path, cmd string, pid int, user, kind string, extra map[string]any) {
	if base == nil {
		return
	}
	attachOCSF(base, ocsf.FromAnnotatedProcess(ocsf.AnnotatedProcessInput{
		ProcessInput: ocsf.ProcessInput{
			EndpointID:  base.EndpointID,
			Hostname:    base.Hostname,
			OS:          base.OS,
			Timestamp:   base.Timestamp,
			PID:         pid,
			ProcessName: name,
			ProcessPath: path,
			CommandLine: cmd,
			User:        user,
		},
		ActivityKind: kind,
		Extra:        extra,
	}, product))
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
