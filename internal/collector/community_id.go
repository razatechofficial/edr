package collector

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
)

// CommunityIDv1 computes the Corelight community-id v1 string for a flow 5-tuple.
// Reference: https://github.com/corelight/community-id-spec
func CommunityIDv1(proto uint8, srcIP, dstIP net.IP, sport, dport uint16) string {
	if s4 := srcIP.To4(); s4 != nil {
		if d4 := dstIP.To4(); d4 != nil {
			return communityIDv1IPv4(proto, s4, d4, sport, dport)
		}
	}
	s16 := srcIP.To16()
	d16 := dstIP.To16()
	if s16 == nil || d16 == nil {
		return ""
	}
	return communityIDv1IPv6(proto, s16, d16, sport, dport)
}

func communityIDv1IPv4(proto uint8, sip, dip net.IP, sport, dport uint16) string {
	a, b, ap, bp := orderEndpoints(sip, dip, sport, dport)
	msg := make([]byte, 0, 2+1+4+4+2+2)
	msg = append(msg, 0, 0) // seed
	msg = append(msg, proto)
	msg = append(msg, a...)
	msg = append(msg, b...)
	msg = binary.BigEndian.AppendUint16(msg, ap)
	msg = binary.BigEndian.AppendUint16(msg, bp)
	sum := sha1.Sum(msg)
	return "1:" + hex.EncodeToString(sum[:])
}

func communityIDv1IPv6(proto uint8, sip, dip net.IP, sport, dport uint16) string {
	a, b, ap, bp := orderEndpoints(sip, dip, sport, dport)
	msg := make([]byte, 0, 2+1+16+16+2+2)
	msg = append(msg, 0, 0)
	msg = append(msg, proto)
	msg = append(msg, a...)
	msg = append(msg, b...)
	msg = binary.BigEndian.AppendUint16(msg, ap)
	msg = binary.BigEndian.AppendUint16(msg, bp)
	sum := sha1.Sum(msg)
	return "1:" + hex.EncodeToString(sum[:])
}

func orderEndpoints(sip, dip net.IP, sport, dport uint16) (a, b net.IP, ap, bp uint16) {
	cmp := bytes.Compare(sip, dip)
	switch {
	case cmp < 0:
		return sip, dip, sport, dport
	case cmp > 0:
		return dip, sip, dport, sport
	default:
		if sport <= dport {
			return sip, dip, sport, dport
		}
		return dip, sip, dport, sport
	}
}

// ProtoNumber maps coarse protocol labels to IANA numbers for community-id.
func ProtoNumber(transport, protocol string) (uint8, bool) {
	t := strings.ToLower(strings.TrimSpace(transport))
	p := strings.ToLower(strings.TrimSpace(protocol))
	switch {
	case strings.Contains(p, "icmp"):
		return 1, true
	case t == "udp" || p == "udp" || strings.Contains(p, "udp"):
		return 17, true
	case t == "tcp" || p == "tcp" || strings.Contains(p, "tcp"):
		return 6, true
	case t == "sctp":
		return 132, true
	default:
		return 0, false
	}
}

// ParseIPString parses an IP for community-id helpers.
func ParseIPString(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}
