package features

import (
	"testing"
)

type mockSupplyChainEvent struct {
	entropies            []float64
	signatureValid       bool
	certChainDepth       int
	certAgeDays          int
	importCount          int
	unusualImportCount   int
	importDeviation      float64
	networkCalloutCount  int
	calloutTimingSecs    float64
	unknownDestCount     int
	hashMatchesManifest  bool
	versionSequenceValid bool
	updateChannelTrusted bool
}

func (m mockSupplyChainEvent) GetSectionEntropies() []float64     { return m.entropies }
func (m mockSupplyChainEvent) GetSignatureValid() bool            { return m.signatureValid }
func (m mockSupplyChainEvent) GetCertChainDepth() int             { return m.certChainDepth }
func (m mockSupplyChainEvent) GetCertAgeDays() int                { return m.certAgeDays }
func (m mockSupplyChainEvent) GetImportCount() int                { return m.importCount }
func (m mockSupplyChainEvent) GetUnusualImportCount() int         { return m.unusualImportCount }
func (m mockSupplyChainEvent) GetImportDeviation() float64        { return m.importDeviation }
func (m mockSupplyChainEvent) GetNetworkCalloutCount() int        { return m.networkCalloutCount }
func (m mockSupplyChainEvent) GetCalloutTimingSecs() float64      { return m.calloutTimingSecs }
func (m mockSupplyChainEvent) GetUnknownDestCount() int           { return m.unknownDestCount }
func (m mockSupplyChainEvent) GetHashMatchesManifest() bool       { return m.hashMatchesManifest }
func (m mockSupplyChainEvent) GetVersionSequenceValid() bool      { return m.versionSequenceValid }
func (m mockSupplyChainEvent) GetUpdateChannelTrusted() bool      { return m.updateChannelTrusted }

func TestSupplyChainExtractor_FeatureCount(t *testing.T) {
	ext := &SupplyChainFeatureExtractor{}
	feats := ext.Extract(mockSupplyChainEvent{})
	if len(feats) != SupplyChainFeatureCount {
		t.Fatalf("expected %d features, got %d", SupplyChainFeatureCount, len(feats))
	}
}

func TestSupplyChainExtractor_EntropyFeatures(t *testing.T) {
	ext := &SupplyChainFeatureExtractor{}
	feats := ext.Extract(mockSupplyChainEvent{
		entropies: []float64{6.0, 7.5, 8.0, 4.0, 3.0},
	})

	if feats[0] != float32(6.0/8.0) {
		t.Errorf("entropy[0] expected %f, got %f", float32(6.0/8.0), feats[0])
	}
	if feats[2] != 1.0 {
		t.Errorf("entropy[2] at 8.0 should clamp to 1.0, got %f", feats[2])
	}
}

func TestSupplyChainExtractor_CertFeatures(t *testing.T) {
	ext := &SupplyChainFeatureExtractor{}
	feats := ext.Extract(mockSupplyChainEvent{
		signatureValid: true,
		certChainDepth: 3,
		certAgeDays:    180,
	})

	if feats[4] != 1.0 {
		t.Error("valid signature should set feat[4] to 1.0")
	}
	if feats[5] != float32(3.0/5.0) {
		t.Errorf("cert chain depth expected %f, got %f", float32(3.0/5.0), feats[5])
	}
	if feats[6] != float32(180.0/365.0) {
		t.Errorf("cert age expected %f, got %f", float32(180.0/365.0), feats[6])
	}
}

func TestSupplyChainExtractor_ImportFeatures(t *testing.T) {
	ext := &SupplyChainFeatureExtractor{}
	feats := ext.Extract(mockSupplyChainEvent{
		importCount:        250,
		unusualImportCount: 10,
		importDeviation:    0.7,
	})

	if feats[8] != float32(250.0/500.0) {
		t.Errorf("import count expected %f, got %f", float32(250.0/500.0), feats[8])
	}
	if feats[9] != float32(10.0/20.0) {
		t.Errorf("unusual import count expected %f, got %f", float32(10.0/20.0), feats[9])
	}
	if feats[10] != 0.7 {
		t.Errorf("import deviation expected 0.7, got %f", feats[10])
	}
}

func TestSupplyChainExtractor_NetworkFeatures(t *testing.T) {
	ext := &SupplyChainFeatureExtractor{}
	feats := ext.Extract(mockSupplyChainEvent{
		networkCalloutCount: 5,
		calloutTimingSecs:   150,
		unknownDestCount:    3,
	})

	if feats[16] != float32(5.0/10.0) {
		t.Errorf("network callout count expected %f, got %f", float32(5.0/10.0), feats[16])
	}
	if feats[17] != float32(150.0/300.0) {
		t.Errorf("callout timing expected %f, got %f", float32(150.0/300.0), feats[17])
	}
	if feats[18] != float32(3.0/5.0) {
		t.Errorf("unknown dest count expected %f, got %f", float32(3.0/5.0), feats[18])
	}
}

func TestSupplyChainExtractor_UpdateFeatures(t *testing.T) {
	ext := &SupplyChainFeatureExtractor{}
	feats := ext.Extract(mockSupplyChainEvent{
		hashMatchesManifest:  true,
		versionSequenceValid: true,
		updateChannelTrusted: false,
	})

	if feats[24] != 1.0 {
		t.Error("hash matches manifest should set feat[24] to 1.0")
	}
	if feats[25] != 1.0 {
		t.Error("version sequence valid should set feat[25] to 1.0")
	}
	if feats[26] != 0.0 {
		t.Error("untrusted channel should leave feat[26] at 0.0")
	}
}

func TestSupplyChainExtractor_EmptyEvent(t *testing.T) {
	ext := &SupplyChainFeatureExtractor{}
	feats := ext.Extract("not-a-real-event")
	if len(feats) != SupplyChainFeatureCount {
		t.Fatalf("expected %d features, got %d", SupplyChainFeatureCount, len(feats))
	}
	for i, v := range feats {
		if v != 0 {
			t.Fatalf("expected all zeros, got non-zero at [%d]=%f", i, v)
		}
	}
}
