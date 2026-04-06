package baseline

import (
	"fmt"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const (
	catProcessParent   = "process.parent"
	catProcessDuration = "process.duration"
	catProcessCmdline  = "process.cmdline"
	catProcessCPU      = "process.cpu"
	catProcessMemory   = "process.memory"
)

// ProcessObservation captures the attributes of a single process execution.
type ProcessObservation struct {
	ProcessName string
	ParentName  string
	CommandLine string
	PID         int
	PPID        int
	DurationMs  float64
	CPUPercent  float64
	MemoryMB    float64
}

// ProcessBaseline tracks normal process behaviour including parent-child
// relationships, execution duration, command-line patterns, and resource usage.
type ProcessBaseline struct {
	engine *BaselineEngine
	logger *zap.Logger

	mu             sync.RWMutex
	parentCounts   map[string]map[string]int // child -> parent -> count
	cmdlineCounts  map[string]map[string]int // process -> cmdline_prefix -> count
}

// NewProcessBaseline creates a process baseline analyser backed by the given engine.
func NewProcessBaseline(engine *BaselineEngine, logger *zap.Logger) *ProcessBaseline {
	return &ProcessBaseline{
		engine:        engine,
		logger:        logger,
		parentCounts:  make(map[string]map[string]int),
		cmdlineCounts: make(map[string]map[string]int),
	}
}

// Observe records a process execution for baseline learning.
func (pb *ProcessBaseline) Observe(obs ProcessObservation) {
	pb.recordParent(obs.ProcessName, obs.ParentName)
	pb.recordCmdline(obs.ProcessName, obs.CommandLine)

	if obs.DurationMs > 0 {
		pb.engine.AddObservation(catProcessDuration, obs.ProcessName, obs.DurationMs)
	}
	if obs.CPUPercent > 0 {
		pb.engine.AddObservation(catProcessCPU, obs.ProcessName, obs.CPUPercent)
	}
	if obs.MemoryMB > 0 {
		pb.engine.AddObservation(catProcessMemory, obs.ProcessName, obs.MemoryMB)
	}
}

// CheckParent returns true if the parent-child relationship is unusual.
func (pb *ProcessBaseline) CheckParent(child, parent string) bool {
	if pb.engine.IsLearning() {
		return false
	}

	pb.mu.RLock()
	defer pb.mu.RUnlock()

	parents, ok := pb.parentCounts[child]
	if !ok {
		return true
	}
	_, seen := parents[parent]
	return !seen
}

// CheckDuration returns true and a deviation score if execution time is anomalous.
func (pb *ProcessBaseline) CheckDuration(name string, durationMs float64) (bool, float64) {
	return pb.engine.IsAnomaly(catProcessDuration, name, durationMs)
}

// CheckCPU returns true and a deviation score if CPU usage is anomalous.
func (pb *ProcessBaseline) CheckCPU(name string, cpuPercent float64) (bool, float64) {
	return pb.engine.IsAnomaly(catProcessCPU, name, cpuPercent)
}

// CheckMemory returns true and a deviation score if memory usage is anomalous.
func (pb *ProcessBaseline) CheckMemory(name string, memoryMB float64) (bool, float64) {
	return pb.engine.IsAnomaly(catProcessMemory, name, memoryMB)
}

func (pb *ProcessBaseline) recordParent(child, parent string) {
	if child == "" || parent == "" {
		return
	}
	pb.mu.Lock()
	defer pb.mu.Unlock()

	parents, ok := pb.parentCounts[child]
	if !ok {
		parents = make(map[string]int)
		pb.parentCounts[child] = parents
	}
	parents[parent]++
	pb.engine.AddObservation(catProcessParent, fmt.Sprintf("%s->%s", parent, child), 1)
}

func (pb *ProcessBaseline) recordCmdline(name, cmdline string) {
	if name == "" || cmdline == "" {
		return
	}

	prefix := cmdlinePrefix(cmdline)
	pb.mu.Lock()
	defer pb.mu.Unlock()

	cmds, ok := pb.cmdlineCounts[name]
	if !ok {
		cmds = make(map[string]int)
		pb.cmdlineCounts[name] = cmds
	}
	cmds[prefix]++
	pb.engine.AddObservation(catProcessCmdline, fmt.Sprintf("%s:%s", name, prefix), 1)
}

func cmdlinePrefix(cmdline string) string {
	parts := strings.Fields(cmdline)
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, " ")
}
