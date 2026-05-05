//go:build windows

package collector

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestExtendWindowsEvtCollectors_StrictProfileForcesDNSCollector(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.SecurityProfile = "strict_complete"
	cfg.Monitoring.DnsClientETWWindows = false
	cols := extendWindowsEvtCollectors(nil, cfg, "ep")
	var foundDNS bool
	for _, c := range cols {
		if c.Name() == "dns" {
			foundDNS = true
			break
		}
	}
	if !foundDNS {
		t.Fatal("expected dns collector in strict profile even when dns_client_etw_windows=false")
	}
}
