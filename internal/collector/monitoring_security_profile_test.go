package collector

import (
	"runtime"
	"strings"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestValidateRegulatedMonitoring_RejectsStubs(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.SecurityProfile = "regulated"

	if err := ValidateRegulatedMonitoring(cfg, []Collector{NewNetworkStubCollector("e")}); err == nil {
		t.Fatal("expected error for network stub")
	}
	if err := ValidateRegulatedMonitoring(cfg, []Collector{NewAuthStubCollector("e")}); err == nil {
		t.Fatal("expected error for auth stub")
	}
	if err := ValidateRegulatedMonitoring(cfg, []Collector{NewFileStubCollector("e")}); err == nil {
		t.Fatal("expected error for file stub")
	}
}

func TestValidateRegulatedMonitoring_RequiresInventory(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.SecurityProfile = "regulated"
	pc, err := NewProcessCollector("e")
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRegulatedMonitoring(cfg, []Collector{pc})
	if err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("want inventory requirement error, got %v", err)
	}
}

func TestInventoryWanted_RegulatedVsStandard(t *testing.T) {
	reg := config.Defaults()
	reg.Monitoring.SecurityProfile = "regulated"
	if !InventoryWanted(reg) {
		t.Fatal("regulated implies inventory")
	}
	std := config.Defaults()
	if InventoryWanted(std) {
		t.Fatal("standard defaults should not imply inventory unless inventory_enabled")
	}
	std.Monitoring.InventoryEnabled = true
	if !InventoryWanted(std) {
		t.Fatal("inventory_enabled should enable L1 collector")
	}
}

func TestIsRegulatedMonitoring_StrictComplete(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.SecurityProfile = "strict_complete"
	if !IsRegulatedMonitoring(cfg) {
		t.Fatal("strict_complete must be treated as regulated profile")
	}
}

func TestValidateRegulatedMonitoring_StrictCompleteRequiresPillars(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.SecurityProfile = "strict_complete"
	pc, err := NewProcessCollector("e")
	if err != nil {
		t.Fatal(err)
	}
	inv := NewInventoryCollector(cfg)
	err = ValidateRegulatedMonitoring(cfg, []Collector{pc, inv})
	if err == nil || !strings.Contains(err.Error(), "required collector") {
		t.Fatalf("expected strict_complete missing collector error, got %v", err)
	}
}

func TestStrictMandatorySources_Conditional(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.SecurityProfile = "strict_complete"
	cfg.Monitoring.PostureEnabled = true
	cfg.Monitoring.AdditionalLogTailPaths = []string{"/var/log/app.log"}
	got := StrictMandatorySources(cfg)
	if !containsName(got, "posture") {
		t.Fatal("expected posture in strict mandatory sources when enabled")
	}
	if !containsName(got, "log_tail") {
		t.Fatal("expected log_tail in strict mandatory sources when paths configured")
	}
}

func TestStrictMandatorySources_OSAchievableBase(t *testing.T) {
	cfg := config.Defaults()
	cfg.Monitoring.SecurityProfile = "strict_complete"
	got := StrictMandatorySources(cfg)
	required := []string{"process", "file", "network", "auth", "registry", "inventory"}
	if runtime.GOOS != "darwin" || cfg.Monitoring.DarwinUnifiedLogDNS || cfg.Monitoring.DarwinLogStreamDNSAlt || len(cfg.Monitoring.DarwinDNSExtraLogPaths) > 0 {
		required = append(required, "dns")
	}
	for _, name := range required {
		if !containsName(got, name) {
			t.Fatalf("goos=%s missing strict mandatory source %q in %v", runtime.GOOS, name, got)
		}
	}
}

func TestStrictBaseMandatorySourcesForGOOS_DarwinDNSGate(t *testing.T) {
	cfg := config.Defaults()
	got := strictBaseMandatorySourcesForGOOS("darwin", cfg)
	if containsName(got, "dns") {
		t.Fatalf("did not expect dns without darwin dns source enablement, got=%v", got)
	}
	cfg.Monitoring.DarwinUnifiedLogDNS = true
	got = strictBaseMandatorySourcesForGOOS("darwin", cfg)
	if !containsName(got, "dns") {
		t.Fatalf("expected dns when darwin unified dns enabled, got=%v", got)
	}
}

func containsName(list []string, name string) bool {
	for _, v := range list {
		if v == name {
			return true
		}
	}
	return false
}
