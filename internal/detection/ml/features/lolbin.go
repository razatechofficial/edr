package features

import (
	"math"
	"strings"
	"unicode"
)

const (
	LOLBinFeatureCount = 64

	lolCmdTokens    = 20
	lolAncestry     = 12
	lolChildSpawn   = 8
	lolScriptInterp = 8
	lolRegistry     = 8
	lolWMICOM       = 8
)

var suspiciousFlags = []string{
	"-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden",
	"-windowstyle hidden", "-bypass", "-exec bypass", "-noninteractive",
	"downloadstring", "downloadfile", "invoke-expression", "iex",
	"frombase64string", "new-object", "net.webclient", "bitstransfer",
	"start-process", "invoke-webrequest", "certutil",
}

var knownLOLBins = map[string]float32{
	"powershell.exe": 0.7, "pwsh.exe": 0.7, "cmd.exe": 0.4,
	"wscript.exe": 0.8, "cscript.exe": 0.8, "mshta.exe": 0.9,
	"regsvr32.exe": 0.8, "rundll32.exe": 0.7, "certutil.exe": 0.8,
	"msiexec.exe": 0.6, "installutil.exe": 0.8, "wmic.exe": 0.7,
	"bitsadmin.exe": 0.7, "schtasks.exe": 0.5, "at.exe": 0.5,
}

// LOLBinFeatureExtractor extracts features from process execution events
// for detecting living-off-the-land binary abuse.
type LOLBinFeatureExtractor struct{}

// Extract produces a 64-dim feature vector from process execution context.
func (e *LOLBinFeatureExtractor) Extract(evt interface{}) []float32 {
	feats := make([]float32, LOLBinFeatureCount)

	type hasCommandLine interface{ GetCommandLine() string }
	type hasProcessName interface{ GetProcessName() string }
	type hasParentName interface{ GetParentProcessName() string }
	type hasAncestors interface{ GetAncestorNames() []string }
	type hasChildCount interface{ GetChildProcessCount() int }
	type hasRegistryOps interface{ GetRegistryOpCount() int }

	var cmdLine, procName, parentName string
	var ancestors []string
	var childCount, regOps int

	if c, ok := evt.(hasCommandLine); ok {
		cmdLine = c.GetCommandLine()
	}
	if p, ok := evt.(hasProcessName); ok {
		procName = p.GetProcessName()
	}
	if p, ok := evt.(hasParentName); ok {
		parentName = p.GetParentProcessName()
	}
	if a, ok := evt.(hasAncestors); ok {
		ancestors = a.GetAncestorNames()
	}
	if c, ok := evt.(hasChildCount); ok {
		childCount = c.GetChildProcessCount()
	}
	if r, ok := evt.(hasRegistryOps); ok {
		regOps = r.GetRegistryOpCount()
	}

	cmdLower := strings.ToLower(cmdLine)
	for i, flag := range suspiciousFlags {
		if i >= lolCmdTokens {
			break
		}
		if strings.Contains(cmdLower, flag) {
			feats[i] = 1.0
		}
	}

	base64Score := countBase64Runs(cmdLine)
	if lolCmdTokens-1 < LOLBinFeatureCount {
		feats[lolCmdTokens-1] = float32(math.Min(float64(base64Score)/100.0, 1.0))
	}

	off := lolCmdTokens
	feats[off] = float32(len(ancestors)) / 10.0
	if risk, ok := knownLOLBins[strings.ToLower(procName)]; ok {
		feats[off+1] = risk
	}
	if risk, ok := knownLOLBins[strings.ToLower(parentName)]; ok {
		feats[off+2] = risk
	}
	for i, anc := range ancestors {
		if i >= 8 {
			break
		}
		if risk, ok := knownLOLBins[strings.ToLower(anc)]; ok {
			feats[off+3+i] = risk
		}
	}

	off = lolCmdTokens + lolAncestry
	feats[off] = float32(math.Min(float64(childCount)/20.0, 1.0))

	off = lolCmdTokens + lolAncestry + lolChildSpawn
	if isScriptInterpreter(procName) {
		feats[off] = 1.0
	}
	if strings.Contains(cmdLower, "|") {
		feats[off+1] = float32(strings.Count(cmdLower, "|")) / 5.0
	}

	off = lolCmdTokens + lolAncestry + lolChildSpawn + lolScriptInterp
	feats[off] = float32(math.Min(float64(regOps)/50.0, 1.0))

	return feats
}

func countBase64Runs(s string) int {
	count := 0
	run := 0
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '/' || r == '=' {
			run++
		} else {
			if run > 40 {
				count += run
			}
			run = 0
		}
	}
	if run > 40 {
		count += run
	}
	return count
}

func isScriptInterpreter(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"powershell", "pwsh", "wscript", "cscript", "mshta", "python", "perl", "ruby"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}
