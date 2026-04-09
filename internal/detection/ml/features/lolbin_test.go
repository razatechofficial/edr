package features

import (
	"strings"
	"testing"
)

type mockLOLBinEvent struct {
	cmdLine     string
	processName string
	parentName  string
	ancestors   []string
	childCount  int
	regOps      int
}

func (m mockLOLBinEvent) GetCommandLine() string        { return m.cmdLine }
func (m mockLOLBinEvent) GetProcessName() string         { return m.processName }
func (m mockLOLBinEvent) GetParentProcessName() string   { return m.parentName }
func (m mockLOLBinEvent) GetAncestorNames() []string     { return m.ancestors }
func (m mockLOLBinEvent) GetChildProcessCount() int      { return m.childCount }
func (m mockLOLBinEvent) GetRegistryOpCount() int        { return m.regOps }

func TestLOLBinExtractor_FeatureCount(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract(mockLOLBinEvent{})
	if len(feats) != LOLBinFeatureCount {
		t.Fatalf("expected %d features, got %d", LOLBinFeatureCount, len(feats))
	}
}

func TestLOLBinExtractor_SuspiciousFlags(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract(mockLOLBinEvent{
		cmdLine: "powershell.exe -enc SomeBase64String -noprofile -w hidden",
	})

	if feats[0] != 1.0 {
		t.Error("-enc should trigger first suspicious flag")
	}
	if feats[3] != 1.0 {
		t.Error("-noprofile should trigger its flag")
	}
}

func TestLOLBinExtractor_KnownProcess(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract(mockLOLBinEvent{
		processName: "mshta.exe",
		parentName:  "cmd.exe",
	})

	off := lolCmdTokens
	if feats[off+1] != 0.9 {
		t.Errorf("mshta.exe should have risk 0.9, got %f", feats[off+1])
	}
	if feats[off+2] != 0.4 {
		t.Errorf("cmd.exe parent should have risk 0.4, got %f", feats[off+2])
	}
}

func TestLOLBinExtractor_AncestorRisk(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract(mockLOLBinEvent{
		ancestors: []string{"cmd.exe", "powershell.exe", "explorer.exe"},
	})

	off := lolCmdTokens + 3
	if feats[off] != 0.4 {
		t.Errorf("cmd.exe ancestor should have risk 0.4, got %f", feats[off])
	}
	if feats[off+1] != 0.7 {
		t.Errorf("powershell.exe ancestor should have risk 0.7, got %f", feats[off+1])
	}
	if feats[off+2] != 0.0 {
		t.Error("explorer.exe is not a known LOLBin")
	}
}

func TestLOLBinExtractor_ChildSpawn(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract(mockLOLBinEvent{childCount: 10})
	off := lolCmdTokens + lolAncestry
	expected := float32(10.0 / 20.0)
	if feats[off] != expected {
		t.Errorf("child spawn feature should be %f, got %f", expected, feats[off])
	}
}

func TestLOLBinExtractor_ScriptInterpreter(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract(mockLOLBinEvent{processName: "powershell.exe"})
	off := lolCmdTokens + lolAncestry + lolChildSpawn
	if feats[off] != 1.0 {
		t.Error("powershell should trigger script interpreter flag")
	}
}

func TestLOLBinExtractor_PipeCount(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract(mockLOLBinEvent{
		cmdLine: "cmd /c whoami | findstr admin | more",
	})
	off := lolCmdTokens + lolAncestry + lolChildSpawn + 1
	if feats[off] <= 0 {
		t.Error("pipe count feature should be positive for piped commands")
	}
}

func TestLOLBinExtractor_RegistryOps(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract(mockLOLBinEvent{regOps: 25})
	off := lolCmdTokens + lolAncestry + lolChildSpawn + lolScriptInterp
	expected := float32(25.0 / 50.0)
	if feats[off] != expected {
		t.Errorf("registry ops feature should be %f, got %f", expected, feats[off])
	}
}

func TestLOLBinExtractor_EmptyEvent(t *testing.T) {
	ext := &LOLBinFeatureExtractor{}
	feats := ext.Extract("not-a-real-event")
	if len(feats) != LOLBinFeatureCount {
		t.Fatalf("expected %d features, got %d", LOLBinFeatureCount, len(feats))
	}
	for i, v := range feats {
		if v != 0 {
			t.Fatalf("expected all zeros for unknown event, got non-zero at [%d]=%f", i, v)
		}
	}
}

func TestCountBase64Runs(t *testing.T) {
	short := "abc"
	if countBase64Runs(short) != 0 {
		t.Error("short strings should not count as base64")
	}

	long := strings.Repeat("A", 50)
	if countBase64Runs(long) != 50 {
		t.Errorf("expected 50, got %d", countBase64Runs(long))
	}

	mixed := strings.Repeat("B", 50) + " " + strings.Repeat("C", 10)
	if countBase64Runs(mixed) != 50 {
		t.Errorf("expected 50, got %d", countBase64Runs(mixed))
	}
}

func TestIsScriptInterpreter(t *testing.T) {
	for _, name := range []string{"powershell.exe", "pwsh", "WScript.exe", "cscript", "mshta.exe", "python3", "perl"} {
		if !isScriptInterpreter(name) {
			t.Errorf("%s should be a script interpreter", name)
		}
	}
	if isScriptInterpreter("notepad.exe") {
		t.Error("notepad.exe should not be a script interpreter")
	}
}
