package features

import (
	"math"
	"net"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

const networkFeatureCount = 19

// NetworkFeatureExtractor extracts per-connection features for anomaly detection.
type NetworkFeatureExtractor struct{}

// Extract produces a 19-dimensional feature vector from a network connection event.
// Features [0..14] match the original 15-dim set. Features [15..18] add byte
// volume and connection timing, mirroring the approach used by rat_c2.go.
func (e *NetworkFeatureExtractor) Extract(conn interface{}) []float32 {
	feats := make([]float32, networkFeatureCount)

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
	default:
		return feats
	}

	logMax := float32(math.Log1p(65535))
	logByteMax := float32(math.Log1p(1 << 30))

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

	// [15] – bytes_in_norm
	feats[15] = float32(math.Log1p(float64(bytesIn))) / logByteMax
	// [16] – bytes_out_norm
	feats[16] = float32(math.Log1p(float64(bytesOut))) / logByteMax
	// [17] – total_bytes_norm
	feats[17] = float32(math.Log1p(float64(bytesIn+bytesOut))) / logByteMax
	// [18] – duration_norm
	if durationMs > 3600000 {
		feats[18] = 1.0
	} else {
		feats[18] = float32(durationMs) / 3600000.0
	}

	return feats
}

// FeatureCount returns the dimensionality of the network feature vector.
func (e *NetworkFeatureExtractor) FeatureCount() int { return networkFeatureCount }

func portCategory(port int) float32 {
	switch {
	case port <= 1023:
		return 0.0
	case port <= 49151:
		return 0.5
	default:
		return 1.0
	}
}

func boolF32(b bool) float32 {
	if b {
		return 1.0
	}
	return 0.0
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsPrivate()
}

func isLoopback(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}
