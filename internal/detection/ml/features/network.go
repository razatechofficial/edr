package features

import (
	"math"
	"net"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

const networkFeatureCount = 15

// NetworkFeatureExtractor extracts per-connection features for anomaly detection.
type NetworkFeatureExtractor struct{}

// Extract produces a 15-dimensional feature vector from a network connection event.
// Features: dest_port_category, src_port_norm, dest_port_norm, time_of_day,
// is_port_{80,443,53,22}, protocol_{tcp,udp}, src_ephemeral, dest_port_linear,
// has_domain, is_private_dest, is_loopback.
func (e *NetworkFeatureExtractor) Extract(conn interface{}) []float32 {
	feats := make([]float32, networkFeatureCount)

	var (
		destPort int
		srcPort  int
		protocol string
		domain   string
		destIP   string
		ts       time.Time
	)

	switch ev := conn.(type) {
	case *schema.NetworkEvent:
		destPort = ev.DestPt
		srcPort = ev.SourcePt
		protocol = ev.Protocol
		domain = ev.Domain
		destIP = ev.DestIP
		ts = ev.Timestamp
	case schema.NetworkEvent:
		destPort = ev.DestPt
		srcPort = ev.SourcePt
		protocol = ev.Protocol
		domain = ev.Domain
		destIP = ev.DestIP
		ts = ev.Timestamp
	default:
		return feats
	}

	logMax := float32(math.Log1p(65535))

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
