package features

import (
	"math"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

const ratC2FeatureCount = 22

// RatC2FeatureExtractor extracts per-connection features for RAT C2 detection.
// Extends the base 15-dim network features with byte-volume, TLS, and
// connection-timing features that are characteristic of C2 beacon traffic.
type RatC2FeatureExtractor struct{}

// Extract produces a 22-dimensional feature vector from a NetworkEvent.
// Features [0..14] mirror the base NetworkFeatureExtractor.
// Features [15..21] add:
//
//	15: bytes_in_norm       – log1p(bytes_in) / log(1<<30)
//	16: bytes_out_norm      – log1p(bytes_out) / log(1<<30)
//	17: total_bytes_norm    – log1p(bytes_in+bytes_out) / log(1<<30)
//	18: duration_norm       – duration_ms / 3600000 (1 hour)
//	19: ja3_entropy         – Shannon entropy of JA3 fingerprint [0,1]
//	20: sni_length_norm     – len(SNI) / 64
//	21: high_port_dest      – float(dest_port > 49151)
func (e *RatC2FeatureExtractor) Extract(conn interface{}) []float32 {
	feats := make([]float32, ratC2FeatureCount)

	var (
		destPort   int
		srcPort    int
		protocol   string
		domain     string
		destIP     string
		ts         time.Time
		bytesIn    uint64
		bytesOut   uint64
		durationMs uint64
		ja3        string
		sni        string
	)

	switch ev := conn.(type) {
	case *schema.NetworkEvent:
		destPort = ev.DestPt
		srcPort = ev.SourcePt
		protocol = ev.Protocol
		domain = ev.Domain
		destIP = ev.DestIP
		ts = ev.Timestamp
		bytesIn = ev.BytesIn
		bytesOut = ev.BytesOut
		durationMs = ev.DurationMs
		ja3 = ev.JA3
		sni = ev.SNI
	case schema.NetworkEvent:
		destPort = ev.DestPt
		srcPort = ev.SourcePt
		protocol = ev.Protocol
		domain = ev.Domain
		destIP = ev.DestIP
		ts = ev.Timestamp
		bytesIn = ev.BytesIn
		bytesOut = ev.BytesOut
		durationMs = ev.DurationMs
		ja3 = ev.JA3
		sni = ev.SNI
	default:
		return feats
	}

	logMax := float32(math.Log1p(65535))
	logByteMax := float32(math.Log1p(1 << 30))

	// [0..14] – base network features
	feats[0] = portCategory(destPort)
	feats[1] = float32(math.Log1p(float64(srcPort))) / logMax
	feats[2] = float32(math.Log1p(float64(destPort))) / logMax
	feats[3] = NormalizeTimeOfDay(ts)
	feats[4] = boolF32(destPort == 80)
	feats[5] = boolF32(destPort == 443)
	feats[6] = boolF32(destPort == 53)
	feats[7] = boolF32(destPort == 22)
	feats[8] = boolF32(strings.EqualFold(protocol, "tcp"))
	feats[9] = boolF32(strings.EqualFold(protocol, "udp"))
	feats[10] = boolF32(srcPort > 1024)
	feats[11] = float32(destPort) / 65535.0
	feats[12] = boolF32(domain != "")
	feats[13] = boolF32(isPrivateIP(destIP))
	feats[14] = boolF32(isLoopback(destIP))

	// [15] – bytes_in_norm: normalized incoming byte count
	feats[15] = float32(math.Log1p(float64(bytesIn))) / logByteMax
	// [16] – bytes_out_norm: normalized outgoing byte count
	feats[16] = float32(math.Log1p(float64(bytesOut))) / logByteMax
	// [17] – total_bytes_norm
	feats[17] = float32(math.Log1p(float64(bytesIn+bytesOut))) / logByteMax
	// [18] – duration_norm: milliseconds normalized to 1 hour
	if durationMs > 3600000 {
		feats[18] = 1.0
	} else {
		feats[18] = float32(durationMs) / 3600000.0
	}
	// [19] – ja3_entropy: Shannon entropy of JA3 fingerprint
	feats[19] = float32(ja3Entropy(ja3))
	// [20] – sni_length_norm: SNI length normalized to 64
	l := len(sni)
	if l > 64 {
		feats[20] = 1.0
	} else {
		feats[20] = float32(l) / 64.0
	}
	// [21] – high_port_dest: ephemeral / dynamic port
	feats[21] = boolF32(destPort > 49151)

	return feats
}

// FeatureCount returns the dimensionality (22).
func (e *RatC2FeatureExtractor) FeatureCount() int { return ratC2FeatureCount }

func ja3Entropy(ja3 string) float64 {
	if len(ja3) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for _, c := range []byte(ja3) {
		freq[c]++
	}
	var ent float64
	l := float64(len(ja3))
	for _, n := range freq {
		p := float64(n) / l
		ent -= p * math.Log2(p)
	}
	// Normalize to [0,1] assuming max entropy ~ log2(128) ≈ 7
	if ent > 7 {
		return 1.0
	}
	return ent / 7.0
}


