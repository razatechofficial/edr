package agent

import (
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

func ensureAlertOCSF(al *schema.Alert, product ocsf.Product) {
	if al == nil || len(al.OCSF) > 0 {
		return
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
	}, product)
	if m := ocsf.EnvelopeToMap(env); len(m) > 0 {
		al.OCSF = m
	}
}
