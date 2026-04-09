package features

import (
	"testing"
)

type mockAIGenEvent struct {
	funcLengths        []int
	maxNesting         int
	repetitionScore    float64
	uniqueStrRatio     float64
	avgStrLength       float64
	strEntropyScore    float64
	uniqueAPICount     int
	totalAPICalls      int
	unusualAPICombos   int
	encodingLayers     int
	varNameEntropy     float64
	ctrlFlowComplexity float64
}

func (m mockAIGenEvent) GetFunctionLengths() []int       { return m.funcLengths }
func (m mockAIGenEvent) GetMaxNestingDepth() int         { return m.maxNesting }
func (m mockAIGenEvent) GetRepetitionScore() float64     { return m.repetitionScore }
func (m mockAIGenEvent) GetUniqueStringRatio() float64   { return m.uniqueStrRatio }
func (m mockAIGenEvent) GetAvgStringLength() float64     { return m.avgStrLength }
func (m mockAIGenEvent) GetStringEntropyScore() float64  { return m.strEntropyScore }
func (m mockAIGenEvent) GetUniqueAPICount() int          { return m.uniqueAPICount }
func (m mockAIGenEvent) GetTotalAPICalls() int           { return m.totalAPICalls }
func (m mockAIGenEvent) GetUnusualAPICombinations() int  { return m.unusualAPICombos }
func (m mockAIGenEvent) GetEncodingLayers() int          { return m.encodingLayers }
func (m mockAIGenEvent) GetVariableNameEntropy() float64 { return m.varNameEntropy }
func (m mockAIGenEvent) GetControlFlowComplexity() float64 { return m.ctrlFlowComplexity }

func TestAIGenExtractor_FeatureCount(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract(mockAIGenEvent{})
	if len(feats) != AIGenFeatureCount {
		t.Fatalf("expected %d features, got %d", AIGenFeatureCount, len(feats))
	}
}

func TestAIGenExtractor_CodeStructure(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract(mockAIGenEvent{
		funcLengths:     []int{50, 60, 70},
		maxNesting:      5,
		repetitionScore: 0.8,
	})

	if feats[0] <= 0 {
		t.Error("mean function length feature should be positive")
	}
	if feats[1] <= 0 {
		t.Error("function length stddev feature should be positive")
	}
	if feats[2] != float32(3.0/100.0) {
		t.Errorf("function count expected %f, got %f", float32(3.0/100.0), feats[2])
	}
	if feats[3] != float32(5.0/10.0) {
		t.Errorf("max nesting expected %f, got %f", float32(5.0/10.0), feats[3])
	}
	if feats[4] != 0.8 {
		t.Errorf("repetition score expected 0.8, got %f", feats[4])
	}
}

func TestAIGenExtractor_StringProfile(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract(mockAIGenEvent{
		uniqueStrRatio:  0.6,
		avgStrLength:    25.0,
		strEntropyScore: 0.9,
	})

	if feats[12] != 0.6 {
		t.Errorf("unique string ratio expected 0.6, got %f", feats[12])
	}
	if feats[13] != float32(25.0/50.0) {
		t.Errorf("avg string length expected %f, got %f", float32(25.0/50.0), feats[13])
	}
	if feats[14] != 0.9 {
		t.Errorf("string entropy expected 0.9, got %f", feats[14])
	}
}

func TestAIGenExtractor_APIDiversity(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract(mockAIGenEvent{
		uniqueAPICount:   50,
		totalAPICalls:    200,
		unusualAPICombos: 5,
	})

	if feats[24] != float32(50.0/200.0) {
		t.Errorf("API diversity ratio expected %f, got %f", float32(50.0/200.0), feats[24])
	}
	if feats[25] != float32(50.0/200.0) {
		t.Errorf("unique API count expected %f, got %f", float32(50.0/200.0), feats[25])
	}
	if feats[26] != float32(5.0/10.0) {
		t.Errorf("unusual combos expected %f, got %f", float32(5.0/10.0), feats[26])
	}
}

func TestAIGenExtractor_Obfuscation(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract(mockAIGenEvent{
		encodingLayers:     3,
		varNameEntropy:     4.0,
		ctrlFlowComplexity: 50.0,
	})

	if feats[32] != float32(3.0/5.0) {
		t.Errorf("encoding layers expected %f, got %f", float32(3.0/5.0), feats[32])
	}
	if feats[33] != float32(4.0/5.0) {
		t.Errorf("variable name entropy expected %f, got %f", float32(4.0/5.0), feats[33])
	}
	if feats[34] != float32(50.0/100.0) {
		t.Errorf("control flow complexity expected %f, got %f", float32(50.0/100.0), feats[34])
	}
}

func TestAIGenExtractor_EmptyEvent(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract("not-a-real-event")
	for i, v := range feats {
		if v != 0 {
			t.Fatalf("expected all zeros, got non-zero at [%d]=%f", i, v)
		}
	}
}

func TestAIGenExtractor_ZeroAPICalls(t *testing.T) {
	ext := &AIGenFeatureExtractor{}
	feats := ext.Extract(mockAIGenEvent{
		uniqueAPICount: 10,
		totalAPICalls:  0,
	})
	if feats[24] != 0.0 {
		t.Errorf("zero total calls should yield 0 ratio, got %f", feats[24])
	}
}
