package features

import (
	"math"
)

const AIGenFeatureCount = 48

// AIGenFeatureExtractor extracts features for detecting AI/LLM-generated
// malware based on code structure patterns and statistical anomalies.
type AIGenFeatureExtractor struct{}

// Extract produces a 48-dim feature vector from executable analysis results.
func (e *AIGenFeatureExtractor) Extract(evt interface{}) []float32 {
	feats := make([]float32, AIGenFeatureCount)

	type hasCodeStructure interface {
		GetFunctionLengths() []int
		GetMaxNestingDepth() int
		GetRepetitionScore() float64
	}
	type hasStringProfile interface {
		GetUniqueStringRatio() float64
		GetAvgStringLength() float64
		GetStringEntropyScore() float64
	}
	type hasAPIDiversity interface {
		GetUniqueAPICount() int
		GetTotalAPICalls() int
		GetUnusualAPICombinations() int
	}
	type hasObfuscation interface {
		GetEncodingLayers() int
		GetVariableNameEntropy() float64
		GetControlFlowComplexity() float64
	}

	if cs, ok := evt.(hasCodeStructure); ok {
		lengths := cs.GetFunctionLengths()
		if len(lengths) > 0 {
			var sum, sumSq float64
			for _, l := range lengths {
				sum += float64(l)
				sumSq += float64(l) * float64(l)
			}
			mean := sum / float64(len(lengths))
			variance := sumSq/float64(len(lengths)) - mean*mean
			feats[0] = float32(math.Min(mean/100.0, 1.0))
			feats[1] = float32(math.Min(math.Sqrt(variance)/50.0, 1.0))
			feats[2] = float32(math.Min(float64(len(lengths))/100.0, 1.0))
		}
		feats[3] = float32(math.Min(float64(cs.GetMaxNestingDepth())/10.0, 1.0))
		feats[4] = float32(math.Min(cs.GetRepetitionScore(), 1.0))
	}

	if sp, ok := evt.(hasStringProfile); ok {
		feats[12] = float32(sp.GetUniqueStringRatio())
		feats[13] = float32(math.Min(sp.GetAvgStringLength()/50.0, 1.0))
		feats[14] = float32(sp.GetStringEntropyScore())
	}

	if api, ok := evt.(hasAPIDiversity); ok {
		total := api.GetTotalAPICalls()
		unique := api.GetUniqueAPICount()
		if total > 0 {
			feats[24] = float32(unique) / float32(total)
		}
		feats[25] = float32(math.Min(float64(unique)/200.0, 1.0))
		feats[26] = float32(math.Min(float64(api.GetUnusualAPICombinations())/10.0, 1.0))
	}

	if ob, ok := evt.(hasObfuscation); ok {
		feats[32] = float32(math.Min(float64(ob.GetEncodingLayers())/5.0, 1.0))
		feats[33] = float32(math.Min(ob.GetVariableNameEntropy()/5.0, 1.0))
		feats[34] = float32(math.Min(ob.GetControlFlowComplexity()/100.0, 1.0))
	}

	return feats
}
