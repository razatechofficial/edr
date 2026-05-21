package agent

import (
	"github.com/razatechofficial/edr/internal/alert"
	"github.com/razatechofficial/edr/internal/schema"
)

func ensureAlertOCSF(al *schema.Alert, productVersion string) {
	if al == nil || len(al.OCSF) > 0 {
		return
	}
	if m := alert.OCSFMap(*al, productVersion); len(m) > 0 {
		al.OCSF = m
	}
}

func marshalAlertOCSF(al schema.Alert, productVersion string) ([]byte, error) {
	return alert.MarshalOCSF(al, productVersion)
}
