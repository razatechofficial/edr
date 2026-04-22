//go:build !cgo

package rules

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// YARAEngine is only functional when built with CGO and libyara (see yara_cgo.go).
type YARAEngine struct{}

// NewYARAEngine is unavailable without CGO; the detection engine disables the YARA layer.
func NewYARAEngine(_ string, _ int, _ int, _ *zap.Logger) (*YARAEngine, error) {
	return nil, fmt.Errorf("yara: not available (built with CGO disabled; use CGO_ENABLED=1 and libyara, or build for the native GOARCH only)")
}

// SetAsyncSink is a no-op in stub builds.
func (e *YARAEngine) SetAsyncSink(_ chan<- YARAScanResult) {}

// EnqueueFileScan always fails in stub builds.
func (e *YARAEngine) EnqueueFileScan(_ string, _ interface{}) bool { return false }

func (e *YARAEngine) LoadRules() error {
	return fmt.Errorf("yara: not available (CGO disabled)")
}

func (e *YARAEngine) ScanFile(_ context.Context, _ string) ([]YARAMatch, error) {
	return nil, fmt.Errorf("yara: not available (CGO disabled)")
}

func (e *YARAEngine) ScanBytes(_ context.Context, _ []byte) ([]YARAMatch, error) {
	return nil, fmt.Errorf("yara: not available (CGO disabled)")
}

func (e *YARAEngine) ScanFileAsync(_ string) <-chan []YARAMatch {
	ch := make(chan []YARAMatch, 1)
	ch <- nil
	close(ch)
	return ch
}

// SubmitAsync is a no-op in stub builds.
func (e *YARAEngine) SubmitAsync(_ scanRequest) bool { return false }

func (e *YARAEngine) Count() int { return 0 }

func (e *YARAEngine) Stop() error { return nil }

func (e *YARAEngine) DroppedJobs() uint64 { return 0 }
