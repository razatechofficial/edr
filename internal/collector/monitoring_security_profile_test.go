package collector

import (
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
