//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/unix"
)

const (
	sizeofNlmsghdr        = 16
	nlSockDiagByFamily    = unix.SOCK_DIAG_BY_FAMILY // 20
	tcpQuintSep           = "|"
	maxInetDiagMsgsPerRun = 8000
)

// InetDiagHiddenSocketSource compares SOCK_DIAG(AF_INET TCP) tuples with /proc/net/tcp (best-effort).
type InetDiagHiddenSocketSource struct {
	endpointID string
	hostname   string
	cfg        config.Config

	emits   atomic.Uint64
	skips   atomic.Uint64 // netlink unavailable
	lastErr atomic.Value
	lastRun atomic.Int64
}

func NewInetDiagHiddenSocketSource(endpointID string, cfg config.Config) *InetDiagHiddenSocketSource {
	h, _ := os.Hostname()
	return &InetDiagHiddenSocketSource{endpointID: endpointID, hostname: h, cfg: cfg}
}

func (s *InetDiagHiddenSocketSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:          "inet_diag_hidden_socket",
		OS:            runtime.GOOS,
		Source:        "netlink",
		Status:        "healthy",
		EPSOut:        s.emits.Load(),
		LastEventUnix: s.lastRun.Load(),
	}.ToMap()
	src["enabled"] = s.cfg.Monitoring.LinuxInetDiagHiddenSocket
	src["skipped_netlink_total"] = s.skips.Load()
	if v := s.lastErr.Load(); v != nil {
		if es, ok := v.(string); ok && es != "" {
			src["last_error"] = es
		}
	}
	return src
}

func (s *InetDiagHiddenSocketSource) Run(ctx context.Context, sink *StreamingSink) error {
	if !s.cfg.Monitoring.LinuxInetDiagHiddenSocket {
		return nil
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	s.probe(ctx, sink)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.probe(ctx, sink)
		}
	}
}

func (s *InetDiagHiddenSocketSource) probe(ctx context.Context, sink *StreamingSink) {
	s.lastErr.Store("")
	now := time.Now().UTC()
	s.lastRun.Store(now.Unix())

	procKeys, err := procNetTCP4Quintuples()
	if err != nil || len(procKeys) == 0 {
		s.lastErr.Store(errString(err))
		return
	}

	nlk, nlErr := sockDiagTCP4Dump(ctx)
	if nlErr != nil || len(nlk) == 0 {
		s.skips.Add(1)
		s.lastErr.Store(errString(nlErr))
		return
	}

	for k := range nlk {
		if ctx.Err() != nil {
			return
		}
		if _, ok := procKeys[k]; !ok && k != "" {
			s.emits.Add(1)
			pe := &schema.ProcessEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventProcess,
					EndpointID:    s.endpointID,
					Timestamp:     now,
					Hostname:      s.hostname,
					OS:            runtime.GOOS,
				},
				ProcessName: "posture.hidden_socket",
				ProcessPath: "netlink_SOCK_DIAG",
				CommandLine: "posture.hidden_socket quintuple=" + k,
				Tags:        []string{"rootkit-iocs", "hidden-socket"},
				Severity:    "high",
			}
			if sink != nil {
				_ = sink.Send(ctx, Telemetry{Process: pe})
			}
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func procNetTCP4Quintuples() (map[string]struct{}, error) {
	raw, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		loc := fields[1]
		rem := fields[2]
		lIP, lPort, ok1 := decodeProcNetAddr(loc)
		rIP, rPort, ok2 := decodeProcNetAddr(rem)
		if !ok1 || !ok2 {
			continue
		}
		out[tcpQuintKey(lIP, lPort, rIP, rPort)] = struct{}{}
	}
	return out, nil
}

func decodeProcNetAddr(s string) (ip string, port uint16, ok bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	ipHex := parts[0]
	portHex := parts[1]
	if len(ipHex) != 8 {
		return "", 0, false
	}
	p, err := parseHexUint16(portHex)
	if err != nil {
		return "", 0, false
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		v, err := parseHexByte(ipHex[i*2 : i*2+2])
		if err != nil {
			return "", 0, false
		}
		b[i] = v
	}
	// /proc/net/tcp stores little-endian IPv4 quads
	return ipStringFromBytes(b[0], b[1], b[2], b[3]), p, true
}

func parseHexByte(s string) (byte, error) {
	var v byte
	for i := 0; i < 2; i++ {
		v <<= 4
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			v += c - '0'
		case c >= 'a' && c <= 'f':
			v += c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v += c - 'A' + 10
		default:
			return 0, unix.EINVAL
		}
	}
	return v, nil
}

func parseHexUint16(s string) (uint16, error) {
	if len(s) != 4 {
		return 0, unix.EINVAL
	}
	var v uint16
	for i := 0; i < 4; i++ {
		v <<= 4
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			v += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			v += uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v += uint16(c-'A') + 10
		default:
			return 0, unix.EINVAL
		}
	}
	return v, nil
}

func ipStringFromBytes(a, b, c, d byte) string {
	return strings.Join([]string{
		strconv.Itoa(int(a)),
		strconv.Itoa(int(b)),
		strconv.Itoa(int(c)),
		strconv.Itoa(int(d)),
	}, ".")
}

func tcpQuintKey(lIP string, lPort uint16, rIP string, rPort uint16) string {
	return lIP + tcpQuintSep + strconv.Itoa(int(lPort)) + "-" + rIP + tcpQuintSep + strconv.Itoa(int(rPort)) + "-tcp"
}

func sockDiagTCP4Dump(ctx context.Context) (map[string]struct{}, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	saNL := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, saNL); err != nil {
		return nil, err
	}
	payload := make([]byte, 32)
	payload[0] = unix.AF_INET
	payload[1] = unix.IPPROTO_TCP
	payload[2] = 0
	payload[3] = 0
	binary.LittleEndian.PutUint32(payload[4:8], ^uint32(0))
	reqLen := uint32(sizeofNlmsghdr + len(payload))
	req := make([]byte, reqLen)
	binary.LittleEndian.PutUint32(req[0:4], reqLen)
	binary.LittleEndian.PutUint16(req[4:6], nlSockDiagByFamily)
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_DUMP)
	binary.LittleEndian.PutUint16(req[6:8], flags)
	binary.LittleEndian.PutUint32(req[8:12], 1)
	binary.LittleEndian.PutUint32(req[12:16], 0)
	copy(req[sizeofNlmsghdr:], payload)

	if err := unix.Sendmsg(fd, req, nil, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, 0); err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	buf := make([]byte, 64*1024)
	msgs := 0
	for {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return out, err
		}
		off := 0
		for off+sizeofNlmsghdr <= n {
			hLen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
			if hLen < sizeofNlmsghdr || off+hLen > n {
				break
			}
			typ := binary.LittleEndian.Uint16(buf[off+4 : off+6])
			switch typ {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				return out, unix.EIO
			default:
				if typ == nlSockDiagByFamily {
					if k, ok := parseInetDiagMsg(buf[off+sizeofNlmsghdr : off+hLen]); ok {
						out[k] = struct{}{}
						msgs++
						if msgs >= maxInetDiagMsgsPerRun {
							return out, nil
						}
					}
				}
			}
			hLen = (hLen + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
			off += hLen
		}
	}
}

// parseInetDiagMsg extracts AF_INET TCP quadruple from inet_diag_msg.
func parseInetDiagMsg(b []byte) (string, bool) {
	if len(b) < 4+24 {
		return "", false
	}
	if b[0] != unix.AF_INET {
		return "", false
	}
	sidOff := 4
	if len(b) < sidOff+24 {
		return "", false
	}
	sport := binary.BigEndian.Uint16(b[sidOff : sidOff+2])
	dport := binary.BigEndian.Uint16(b[sidOff+2 : sidOff+4])
	src := binary.BigEndian.Uint32(b[sidOff+4 : sidOff+8])
	dst := binary.BigEndian.Uint32(b[sidOff+8 : sidOff+12])
	sip := ipStringFromBytes(byte(src>>24), byte(src>>16), byte(src>>8), byte(src))
	dip := ipStringFromBytes(byte(dst>>24), byte(dst>>16), byte(dst>>8), byte(dst))
	return tcpQuintKey(sip, sport, dip, dport), true
}
