package response

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/razatechofficial/edr/internal/detection"
	"go.uber.org/zap"
)

func TestDefaultExecutorCollectArtifacts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	e := &DefaultActionExecutor{
		Logger:       zap.NewNop(),
		HostID:       "endpoint-1",
		ForensicsDir: dir,
		Eng:          newTestEngine(t),
	}
	d := detection.Detection{
		ID:       "alert-synth",
		RuleID:   "rule-test",
		Severity: detection.P2,
	}
	if err := e.Execute(context.Background(), "collect_artifacts", nil, d); err != nil {
		t.Fatal(err)
	}

	// The point of the action is that evidence exists afterwards. This test
	// previously passed with the bundle discarded, which is what made the
	// defect survive.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read artifact dir: %v", err)
	}
	var written []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			written = append(written, entry.Name())
		}
	}
	if len(written) != 1 {
		t.Fatalf("wrote %v, want exactly one bundle", written)
	}
	if !strings.Contains(written[0], "alert-synth") {
		t.Errorf("bundle %q is not attributable to its alert", written[0])
	}
}

// Asking for evidence with nowhere to put it is a misconfiguration, and
// reporting success would recreate the defect this action had.
func TestCollectArtifactsFailsWhenThereIsNowhereToWrite(t *testing.T) {
	t.Parallel()
	e := &DefaultActionExecutor{
		Logger: zap.NewNop(),
		HostID: "endpoint-1",
		Eng:    newTestEngine(t),
	}
	err := e.Execute(context.Background(), "collect_artifacts", nil, detection.Detection{ID: "a"})
	if err == nil {
		t.Fatal("collect_artifacts reported success with no artifact directory")
	}
	if !strings.Contains(err.Error(), "artifact directory") {
		t.Errorf("err = %v; want it to name the missing configuration", err)
	}
}
