package collector

import (
	"context"

	"github.com/razatechofficial/edr/internal/schema"
)

// Telemetry is one unit of host telemetry (at most one payload pointer is set).
type Telemetry struct {
	Process       *schema.ProcessEvent
	Network       *schema.NetworkEvent
	Auth          *schema.AuthEvent
	Task          *schema.TaskEvent
	Service       *schema.ServiceEvent
	Credential    *schema.CredentialAccessEvent
	Memory        *schema.MemoryEvent
	Container     *schema.ContainerEvent
	SecPolicy     *schema.SecurityPolicyEvent
	Tamper        *schema.TamperEvent
	Persistence   *schema.PersistenceEvent
	Privacy       *schema.PrivacyEvent
	Gatekeeper    *schema.GatekeeperBypassEvent
	Dropped       *schema.DroppedEventsEvent
	TIStatus      *schema.TIStatusEvent
	FeatureStatus *schema.FeatureStatusEvent
	File          *schema.FileEvent
	Fork          *schema.ForkEvent
	Registry      *schema.RegistryEvent
	Injection     *schema.ProcessInjectionEvent
}

// Collector gathers host telemetry for the detection engine.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Telemetry, error)
}
