package response

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/razatechofficial/edr/internal/detection"
	"github.com/razatechofficial/edr/internal/schema"
	"go.uber.org/zap"
)

// Scenario: T1486 ransomware detection drives PB-002: snapshot → isolate → forensics → alert
// (network isolate is stubbed via integrationTestNetworkIsolateHook so we do not touch firewall rules.)
func TestResponsePipeline_RansomwareP0(t *testing.T) {
	forensicsDir := t.TempDir()
	quarantineDir := t.TempDir()
	malwareDir := t.TempDir()
	malwareFile := filepath.Join(malwareDir, "ransom.exe")
	if err := os.WriteFile(malwareFile, []byte("MALWARE"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	playbookPath := filepath.Join(filepath.Dir(thisFile), "testdata", "playbooks_ransomware.yml")
	if _, err := os.Stat(playbookPath); err != nil {
		t.Fatalf("playbook file: %v", err)
	}
	integrationTestNetworkIsolateHook = func(_ context.Context, e *DefaultActionExecutor, params map[string]interface{}, d detection.Detection, _ *zap.Logger) error {
		dur := intParamAny(params, "duration_minutes")
		noop := func(context.Context) error { return nil }
		e.registerContainment(d, ActionNetworkIsolate, "network", dur, noop)
		return nil
	}
	t.Cleanup(func() { integrationTestNetworkIsolateHook = nil })

	eng, err := NewEngine(EngineConfig{
		PlaybooksPath: playbookPath,
		ForensicsDir:  forensicsDir,
		QuarantineDir: quarantineDir,
		AgentIP:       "127.0.0.1",
		HostID:        "integration-test",
		Logger:        zap.NewNop(),
		Approval:      ApprovalConfig{Mode: "auto"},
		ActionEng:     nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	eng.Start(context.Background())
	t.Cleanup(eng.Stop)

	d := detection.Detection{
		ID:          "integ-ransom-1",
		TechniqueID: "T1486",
		Severity:    detection.P0,
		Confidence:  0.95,
		Source:      detection.SourceBehavioral,
		Event: &detection.EventPayload{
			File: &schema.FileEvent{
				Path:      malwareFile,
				Operation: "write",
				ActorPID:  os.Getpid(),
			},
		},
	}
	if err := eng.Handle(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(forensicsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("forensics bundle should be created under ForensicsDir")
	}
	st := eng.Stats()
	if st.ActionsExecuted == 0 {
		t.Fatal("expected at least one handle execution")
	}
	acs := eng.ActiveContainments()
	if len(acs) == 0 {
		t.Fatal("expected stub network isolate to register a containment")
	}
	t.Logf("active containments: %d", len(acs))
}
