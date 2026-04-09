package features

import (
	"math"
)

const SupplyChainFeatureCount = 32

// SupplyChainFeatureExtractor extracts features for detecting supply chain
// attacks -- tampered updates, compromised build pipelines, backdoored deps.
type SupplyChainFeatureExtractor struct{}

// Extract produces a 32-dim feature vector from binary and update metadata.
func (e *SupplyChainFeatureExtractor) Extract(evt interface{}) []float32 {
	feats := make([]float32, SupplyChainFeatureCount)

	type hasEntropy interface{ GetSectionEntropies() []float64 }
	type hasCert interface {
		GetSignatureValid() bool
		GetCertChainDepth() int
		GetCertAgeDays() int
	}
	type hasImports interface {
		GetImportCount() int
		GetUnusualImportCount() int
		GetImportDeviation() float64
	}
	type hasNetwork interface {
		GetNetworkCalloutCount() int
		GetCalloutTimingSecs() float64
		GetUnknownDestCount() int
	}
	type hasUpdate interface {
		GetHashMatchesManifest() bool
		GetVersionSequenceValid() bool
		GetUpdateChannelTrusted() bool
	}

	if h, ok := evt.(hasEntropy); ok {
		entropies := h.GetSectionEntropies()
		for i, ent := range entropies {
			if i >= 4 {
				break
			}
			feats[i] = float32(math.Min(ent/8.0, 1.0))
		}
	}

	if c, ok := evt.(hasCert); ok {
		if c.GetSignatureValid() {
			feats[4] = 1.0
		}
		feats[5] = float32(math.Min(float64(c.GetCertChainDepth())/5.0, 1.0))
		feats[6] = float32(math.Min(float64(c.GetCertAgeDays())/365.0, 1.0))
	}

	if im, ok := evt.(hasImports); ok {
		feats[8] = float32(math.Min(float64(im.GetImportCount())/500.0, 1.0))
		feats[9] = float32(math.Min(float64(im.GetUnusualImportCount())/20.0, 1.0))
		feats[10] = float32(math.Min(im.GetImportDeviation(), 1.0))
	}

	if n, ok := evt.(hasNetwork); ok {
		feats[16] = float32(math.Min(float64(n.GetNetworkCalloutCount())/10.0, 1.0))
		feats[17] = float32(math.Min(n.GetCalloutTimingSecs()/300.0, 1.0))
		feats[18] = float32(math.Min(float64(n.GetUnknownDestCount())/5.0, 1.0))
	}

	if u, ok := evt.(hasUpdate); ok {
		if u.GetHashMatchesManifest() {
			feats[24] = 1.0
		}
		if u.GetVersionSequenceValid() {
			feats[25] = 1.0
		}
		if u.GetUpdateChannelTrusted() {
			feats[26] = 1.0
		}
	}

	return feats
}
