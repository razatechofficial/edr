package alert

import (
	"encoding/json"
	"fmt"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

// OCSFMap returns the OCSF Detection Finding map for an alert.
func OCSFMap(al schema.Alert, productVersion string) map[string]any {
	if len(al.OCSF) > 0 {
		return al.OCSF
	}
	env := ocsf.FromDetectionAlert(ocsf.AlertInput{
		AlertID:       al.AlertID,
		RuleID:        al.RuleID,
		EndpointID:    al.EndpointID,
		Title:         al.Title,
		Description:   al.Description,
		Severity:      string(al.Severity),
		Score:         al.Score,
		Timestamp:     al.Timestamp,
		ProcessPID:    al.ProcessPID,
		ProcessName:   al.ProcessName,
		ProcessPath:   al.ProcessPath,
		CommandLine:   al.CommandLine,
		FilePath:      al.FilePath,
		FileSHA256:    al.FileSHA256,
		FileOperation: al.FileOperation,
		Protocol:      al.Protocol,
		DestIP:        al.DestIP,
		DestPort:      al.DestPort,
		Domain:        al.Domain,
		SourceIP:      al.SourceIP,
		URL:           al.URL,
		User:          al.User,
		AuthType:      al.AuthType,
		Outcome:       al.Outcome,

		TechniqueID:   al.TechniqueID,
		TechniqueName: al.TechniqueName,
		TacticID:      al.TacticID,
		TacticName:    al.TacticName,
		Confidence:    al.Confidence,
		RiskScore:     al.RiskScore,
		Disposition:   al.Disposition,
		Hostname:      al.Hostname,
		DetectionLayer: al.DetectionLayer,
	}, ocsf.DefaultProduct(productVersion))
	return ocsf.EnvelopeToMap(env)
}

// MarshalOCSF serializes an alert as an OCSF 1.3 Detection Finding JSON object.
func MarshalOCSF(al schema.Alert, productVersion string) ([]byte, error) {
	m := OCSFMap(al, productVersion)
	if len(m) == 0 {
		return nil, fmt.Errorf("alert: missing OCSF envelope")
	}
	return json.Marshal(m)
}
