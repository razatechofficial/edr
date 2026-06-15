package features

import (
	"math"
	"os"
	"regexp"
	"strings"

	"github.com/razatechofficial/edr/internal/schema"
)

const AIGenFeatureCount = 48

var (
	aigenControlKW = map[string]bool{
		"for": true, "while": true, "if": true, "elif": true, "else": true,
		"try": true, "except": true, "catch": true, "switch": true, "case": true,
	}
	aigenSecuritySensitive = map[string]bool{
		"exec": true, "eval": true, "compile": true, "__import__": true,
		"getattr": true, "setattr": true, "delattr": true, "subprocess": true,
		"os.system": true, "os.popen": true, "shutil": true, "pickle": true,
		"marshal": true, "shelve": true, "ctypes": true, "socket": true,
		"requests": true, "urllib": true, "ftplib": true, "telnetlib": true,
	}
	aigenSyscallWords = map[string]bool{
		"read": true, "write": true, "open": true, "close": true, "exec": true,
		"fork": true, "connect": true, "listen": true, "send": true, "recv": true,
		"mmap": true, "brk": true, "ioctl": true, "fcntl": true, "stat": true,
		"lstat": true, "access": true, "chmod": true, "chown": true,
	}
	aigenNetworkWords = map[string]bool{
		"http": true, "https": true, "url": true, "ip": true, "dns": true,
		"tcp": true, "udp": true, "socket": true, "proxy": true, "server": true,
		"client": true, "connect": true, "bind": true, "listen": true, "accept": true,
		"send": true, "recv": true,
	}
	aigenHedgeWords = map[string]bool{
		"might": true, "may": true, "could": true, "would": true, "should": true,
		"perhaps": true, "probably": true, "possibly": true, "maybe": true,
		"potentially": true, "typically": true, "generally": true, "often": true,
		"sometimes": true, "usually": true,
	}
	aigenExplanationWords = map[string]bool{
		"because": true, "since": true, "therefore": true, "however": true,
		"thus": true, "hence": true, "furthermore": true, "moreover": true,
		"additionally": true, "consequently": true, "specifically": true,
		"generally": true, "typically": true, "usually": true, "often": true,
		"sometimes": true, "rarely": true, "frequently": true, "note": true,
		"hint": true, "tip": true, "warning": true, "important": true,
	}
	reCamelCase   = regexp.MustCompile(`\b[A-Z][a-z]+(?:[A-Z][a-z]+)*\b`)
	reSnakeCase   = regexp.MustCompile(`\b[a-z]+(?:_[a-z]+)+\b`)
	reUpperCase   = regexp.MustCompile(`\b[A-Z_]{2,}\b`)
	reShortVars   = regexp.MustCompile(`\b[a-z]{1,2}\b`)
	reFuncCalls   = regexp.MustCompile(`\b\w+\(`)
	reBase64Like  = regexp.MustCompile(`[A-Za-z0-9+/]{30,}={0,2}`)
	reHexPatterns = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	reDocComment  = regexp.MustCompile(`"""|'''|/\*\*|///`)
	reFuncDef     = regexp.MustCompile(`\b(def |function |public|private|protected).*\(`)
)

// AIGenFeatureExtractor extracts features for detecting AI/LLM-generated
// malware based on code structure patterns and statistical anomalies.
type AIGenFeatureExtractor struct {
	// MaxFileSize is the maximum file size in bytes to read (default 10MB).
	MaxFileSize int64
}

func (e *AIGenFeatureExtractor) maxSize() int64 {
	if e.MaxFileSize > 0 {
		return e.MaxFileSize
	}
	return 10 * 1024 * 1024
}

// Extract produces a 48-dim feature vector from file content.
// It reads the file from disk via a FileEvent's Path (or ProcessEvent's ProcessPath/CommandLine),
// then computes the same 48 structural features as the Python code adapter.
func (e *AIGenFeatureExtractor) Extract(evt interface{}) []float32 {
	feats := make([]float32, AIGenFeatureCount)

	content := e.readContent(evt)
	if content == "" {
		return feats
	}

	e.extractAIGenFeatures(content, feats)
	return feats
}

func (e *AIGenFeatureExtractor) readContent(evt interface{}) string {
	switch v := evt.(type) {
	case *schema.FileEvent:
		if v == nil {
			return ""
		}
		p := strings.TrimSpace(v.Path)
		if p == "" {
			return ""
		}
		data, err := os.ReadFile(p)
		if err != nil || int64(len(data)) > e.maxSize() {
			return ""
		}
		return string(data)

	case schema.FileEvent:
		p := strings.TrimSpace(v.Path)
		if p == "" {
			return ""
		}
		data, err := os.ReadFile(p)
		if err != nil || int64(len(data)) > e.maxSize() {
			return ""
		}
		return string(data)

	case *schema.ProcessEvent:
		if v == nil {
			return ""
		}
		// Try ProcessPath first, fall back to CommandLine
		p := strings.TrimSpace(v.ProcessPath)
		if p != "" {
			if data, err := os.ReadFile(p); err == nil && int64(len(data)) <= e.maxSize() {
				return string(data)
			}
		}
		return v.CommandLine

	case schema.ProcessEvent:
		p := strings.TrimSpace(v.ProcessPath)
		if p != "" {
			if data, err := os.ReadFile(p); err == nil && int64(len(data)) <= e.maxSize() {
				return string(data)
			}
		}
		return v.CommandLine

	case interface{ GetPath() string }:
		p := strings.TrimSpace(v.GetPath())
		if p == "" {
			return ""
		}
		data, err := os.ReadFile(p)
		if err != nil || int64(len(data)) > e.maxSize() {
			return ""
		}
		return string(data)

	case interface{ GetCommandLine() string }:
		return v.GetCommandLine()
	}

	return ""
}

func (e *AIGenFeatureExtractor) extractAIGenFeatures(content string, feats []float32) {
	lines := strings.Split(content, "\n")
	nonBlank := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			nonBlank = append(nonBlank, l)
		}
	}

	words := strings.Fields(content)
	if len(words) == 0 || len(nonBlank) == 0 {
		return
	}

	chars := []rune(content)

	lineLengths := make([]float64, len(nonBlank))
	for i, l := range nonBlank {
		lineLengths[i] = float64(len([]rune(l)))
	}
	meanLL := meanFloat64(lineLengths)
	stdLL := stdFloat64(lineLengths, meanLL)

	// [0:8] Code structure entropy
	feats[0] = float32(math.Min(stdLL/30.0, 1.0))
	feats[1] = float32(math.Min(meanLL/80.0, 1.0))

	blankCount := 0
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			blankCount++
		}
	}
	blankRatio := float64(blankCount) / math.Max(float64(len(lines)), 1)
	feats[2] = float32(math.Min(blankRatio*3.0, 1.0))

	if len(lineLengths) > 0 {
		maxLenRatio := maxFloat64(lineLengths) / math.Max(meanLL+1, 1)
		feats[3] = float32(math.Min(maxLenRatio/5.0, 1.0))
	}

	indents := make([]float64, 0, len(nonBlank))
	for _, l := range nonBlank {
		trimmed := strings.TrimLeft(l, " \t")
		indent := float64(len([]rune(l)) - len([]rune(trimmed)))
		if indent > 0 || trimmed != "" {
			indents = append(indents, indent)
		}
	}
	if len(indents) > 0 {
		meanIndent := meanFloat64(indents)
		stdIndent := stdFloat64(indents, meanIndent)
		feats[4] = float32(math.Min(meanIndent/20.0, 1.0))
		feats[5] = float32(math.Min(stdIndent/10.0, 1.0))
	}

	// [8:16] Comment profile
	commentLines := 0
	docstringLines := 0
	explanationCount := 0
	for _, l := range nonBlank {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "///") {
			commentLines++
		}
	}
	for _, l := range lines {
		if reDocComment.MatchString(l) {
			docstringLines++
		}
	}
	wordLower := strings.ToLower(content)
	for _, w := range strings.Fields(wordLower) {
		w = strings.Trim(w, ".,!?;:()[]{}")
		if aigenExplanationWords[w] {
			explanationCount++
		}
	}

	feats[8] = float32(math.Min(float64(commentLines)/(math.Max(float64(len(nonBlank))*0.3, 1)), 1.0))
	feats[9] = float32(math.Min(float64(docstringLines)/(math.Max(float64(len(lines))*0.1, 1)), 1.0))
	feats[10] = float32(math.Min(float64(explanationCount)/(math.Max(float64(len(words))*0.05, 1)), 1.0))

	codeLines := len(nonBlank) - commentLines
	if codeLines > 0 {
		feats[11] = float32(math.Min(float64(commentLines)/float64(codeLines), 1.0))
	}

	// [16:24] Code complexity
	branchCount := 0
	for _, w := range words {
		w = strings.Trim(w, "():")
		if aigenControlKW[w] {
			branchCount++
		}
	}
	feats[16] = float32(math.Min(float64(branchCount)/(math.Max(float64(len(nonBlank))*0.2, 1)), 1.0))

	funcDefs := reFuncDef.FindAllString(content, -1)
	feats[17] = float32(math.Min(float64(len(funcDefs))/(math.Max(float64(len(nonBlank))*0.05, 1)), 1.0))

	uniqueTokens := make(map[string]bool)
	for _, w := range words {
		w = strings.Trim(w, ".,!?;:()[]{}<>'\"")
		w = strings.ToLower(w)
		uniqueTokens[w] = true
	}
	uniqueRatio := float64(len(uniqueTokens)) / math.Max(float64(len(words)), 1)
	feats[18] = float32(math.Min(uniqueRatio, 1.0))

	bracketDepth := 0
	maxDepth := 0
	for _, c := range chars {
		if c == '(' || c == '{' || c == '[' {
			bracketDepth++
			if bracketDepth > maxDepth {
				maxDepth = bracketDepth
			}
		} else if c == ')' || c == '}' || c == ']' {
			if bracketDepth > 0 {
				bracketDepth--
			}
		}
	}
	feats[19] = float32(math.Min(float64(maxDepth)/10.0, 1.0))

	// [24:32] Naming conventions
	camelCase := len(reCamelCase.FindAllString(content, -1))
	snakeCase := len(reSnakeCase.FindAllString(content, -1))
	upperCase := len(reUpperCase.FindAllString(content, -1))
	totalNames := camelCase + snakeCase + upperCase + 1

	feats[24] = float32(math.Min(float64(camelCase)/float64(totalNames), 1.0))
	feats[25] = float32(math.Min(float64(snakeCase)/float64(totalNames), 1.0))
	feats[26] = float32(math.Min(float64(upperCase)/float64(totalNames), 1.0))

	shortVars := len(reShortVars.FindAllString(content, -1))
	feats[27] = float32(math.Min(float64(shortVars)/(math.Max(float64(len(words))*0.1, 1)), 1.0))

	funcCalls := reFuncCalls.FindAllString(content, -1)
	feats[28] = float32(math.Min(float64(len(funcCalls))/(math.Max(float64(len(nonBlank))*0.5, 1)), 1.0))

	// [32:40] Obfuscation indicators
	encodedPatterns := reBase64Like.FindAllString(content, -1)
	feats[32] = float32(math.Min(float64(len(encodedPatterns))/5.0, 1.0))

	hexPatterns := reHexPatterns.FindAllString(content, -1)
	feats[33] = float32(math.Min(float64(len(hexPatterns))/(math.Max(float64(len(chars))*0.02, 1)), 1.0))

	if len(lineLengths) > 0 && stdLL > 0 {
		feats[34] = float32(math.Min(meanLL/(stdLL+1), 1.0))
	}

	rareChars := 0
	for _, c := range chars {
		if c > 127 {
			rareChars++
		}
	}
	feats[35] = float32(math.Min(float64(rareChars)/(math.Max(float64(len(chars))*0.02, 1)), 1.0))

	// [40:48] Behavioral & keyword patterns
	securityCount := 0
	syscallCount := 0
	networkCount := 0
	hedgeCount := 0
	for _, w := range words {
		w = strings.Trim(w, "(),;")
		wLower := strings.ToLower(w)
		if aigenSecuritySensitive[w] || aigenSecuritySensitive[wLower] {
			securityCount++
		}
		if aigenSyscallWords[wLower] {
			syscallCount++
		}
		if aigenNetworkWords[wLower] {
			networkCount++
		}
		if aigenHedgeWords[wLower] {
			hedgeCount++
		}
	}

	feats[40] = float32(math.Min(float64(securityCount)/(math.Max(float64(len(words))*0.05, 1)), 1.0))
	feats[41] = float32(math.Min(float64(syscallCount)/(math.Max(float64(len(words))*0.05, 1)), 1.0))
	feats[42] = float32(math.Min(float64(networkCount)/(math.Max(float64(len(words))*0.03, 1)), 1.0))
	feats[43] = float32(math.Min(float64(hedgeCount)/(math.Max(float64(len(words))*0.03, 1)), 1.0))

	// Unique token ratio inverted (low = more repetitive = more AI-like)
	feats[44] = float32(1.0 - math.Min(uniqueRatio, 1.0))

	// Line length coefficient of variation
	if meanLL > 0 {
		feats[45] = float32(math.Min(stdLL/meanLL, 1.0))
	}
}

func meanFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stdFloat64(vals []float64, mean float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	var sumSq float64
	for _, v := range vals {
		d := v - mean
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(vals)))
}

func maxFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

