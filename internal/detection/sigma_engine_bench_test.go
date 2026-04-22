package detection

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection/rules"
	"github.com/razatechofficial/edr/pkg/events"
)

const benchSigmaRule = `title: Bench Process
id: bench-process
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '.exe'
  condition: selection
level: medium
`

func BenchmarkDetectionEngine_Process(b *testing.B) {
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bench.yml"), []byte(benchSigmaRule), 0o644); err != nil {
		b.Fatal(err)
	}
	se, err := rules.NewSigmaEngine(dir, zap.NewNop())
	if err != nil {
		b.Fatal(err)
	}
	e := &Engine{
		logger:  zap.NewNop(),
		running: true,
		alertCh: make(chan *events.Alert, 1024),
		scorer:  NewScoringEngine(),
		deduper: NewAlertDeduper(5*time.Second, ""),
		sigma:   se,
	}
	event := map[string]interface{}{
		"event_type":  "process",
		"pid":         1234,
		"endpoint_id": "bench",
		"Image":       `C:\Windows\System32\notepad.exe`,
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = e.Process(context.Background(), event)
		}
	})
}
