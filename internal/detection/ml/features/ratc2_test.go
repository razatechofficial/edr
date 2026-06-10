package features

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestRatC2FeatureExtractorDim(t *testing.T) {
	t.Parallel()
	ex := &RatC2FeatureExtractor{}
	feats := ex.Extract(schema.NetworkEvent{
		SourcePt: 53000,
		DestPt:   443,
		Protocol: "tcp",
		Domain:   "example.com",
		DestIP:   "8.8.8.8",
		BaseEvent: schema.BaseEvent{
			Timestamp: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
		},
	})
	if len(feats) != ex.FeatureCount() {
		t.Fatalf("unexpected feature count: got=%d want=%d", len(feats), ex.FeatureCount())
	}
	if feats[5] != 1.0 {
		t.Fatalf("expected https port feature flag at [5]")
	}
	if feats[8] != 1.0 {
		t.Fatalf("expected tcp feature flag at [8]")
	}
}

func TestRatC2FeatureExtractorBytes(t *testing.T) {
	t.Parallel()
	ex := &RatC2FeatureExtractor{}
	feats := ex.Extract(schema.NetworkEvent{
		SourcePt:  33000,
		DestPt:    8080,
		Protocol:  "tcp",
		BytesIn:   4096,
		BytesOut:  256,
		DurationMs: 15000,
		JA3:       "771,4865-4866-4867,0-23-65281,29-23-24,0",
		SNI:       "evil-c2.example.com",
		BaseEvent: schema.BaseEvent{
			Timestamp: time.Date(2026, 6, 1, 14, 30, 0, 0, time.UTC),
		},
	})
	if len(feats) != ex.FeatureCount() {
		t.Fatalf("unexpected feature count: got=%d want=%d", len(feats), ex.FeatureCount())
	}
	// [15] bytes_in_norm should be > 0
	if feats[15] <= 0 {
		t.Fatalf("expected bytes_in_norm > 0, got %.4f", feats[15])
	}
	// [16] bytes_out_norm
	if feats[16] <= 0 {
		t.Fatalf("expected bytes_out_norm > 0, got %.4f", feats[16])
	}
	// [18] duration_norm should be ~0.00417 (15000 / 3600000)
	if feats[18] <= 0 || feats[18] > 0.01 {
		t.Fatalf("expected duration_norm ~0.0042, got %.6f", feats[18])
	}
	// [19] ja3_entropy should be > 0 (non-empty JA3)
	if feats[19] <= 0 {
		t.Fatalf("expected ja3_entropy > 0, got %.4f", feats[19])
	}
	if feats[20] <= 0 || feats[20] > 0.5 {
		t.Fatalf("expected reasonable sni_length_norm, got %.4f", feats[20])
	}
	// [21] high_port_dest – 8080 <= 49151
	if feats[21] != 0 {
		t.Fatalf("expected high_port_dest 0 for port 8080, got %.0f", feats[21])
	}
}

func TestRatC2FeatureExtractorEphemeral(t *testing.T) {
	t.Parallel()
	ex := &RatC2FeatureExtractor{}
	feats := ex.Extract(schema.NetworkEvent{
		DestPt: 54321,
		BaseEvent: schema.BaseEvent{
			Timestamp: time.Now(),
		},
	})
	// [21] high_port_dest – 54321 > 49151
	if feats[21] != 1.0 {
		t.Fatalf("expected high_port_dest 1 for port 54321, got %.0f", feats[21])
	}
}

func TestRatC2FeatureExtractorEmptyJA3(t *testing.T) {
	t.Parallel()
	ex := &RatC2FeatureExtractor{}
	feats := ex.Extract(schema.NetworkEvent{
		DestPt: 443,
		JA3:    "",
		BaseEvent: schema.BaseEvent{
			Timestamp: time.Now(),
		},
	})
	// [19] empty JA3 → entropy 0
	if feats[19] != 0 {
		t.Fatalf("expected ja3_entropy 0 for empty JA3, got %.4f", feats[19])
	}
}
