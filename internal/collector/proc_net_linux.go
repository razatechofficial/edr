//go:build linux

package collector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// procNetLocalPortsTCP returns all local TCP port numbers seen in /proc/net/tcp and tcp6,
// decoding the "local_address" field (IPv4 tcp and IPv6 tcp6 layouts).
func procNetLocalPortsTCP() (map[int]struct{}, error) {
	m := map[int]struct{}{}
	for _, fn := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		ports, err := readProcNetPortsFile(fn)
		if err != nil {
			return nil, err
		}
		for p := range ports {
			m[p] = struct{}{}
		}
	}
	return m, nil
}

// procNetLocalPortsUDP returns UDP local port numbers from /proc/net/udp and udp6.
func procNetLocalPortsUDP() (map[int]struct{}, error) {
	m := map[int]struct{}{}
	for _, fn := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		ports, err := readProcNetPortsFile(fn)
		if err != nil {
			return nil, err
		}
		for p := range ports {
			m[p] = struct{}{}
		}
	}
	return m, nil
}

func readProcNetPortsFile(path string) (map[int]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[int]struct{}{}
	sc := bufio.NewScanner(f)
	header := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if header {
			header = false
			continue // skip titles
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localHex := strings.Split(fields[1], ":")
		if len(localHex) != 2 {
			continue
		}
		portHex := localHex[len(localHex)-1]
		p, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		out[int(p)] = struct{}{}
	}
	return out, sc.Err()
}

// parseProcNetLineLocalPort parses a single "sl local_address remote_address..." line (for tests).
func parseProcNetLineLocalPort(line string) int {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return 0
	}
	ipPort := strings.Split(fields[1], ":")
	if len(ipPort) < 2 {
		return 0
	}
	portHex := ipPort[len(ipPort)-1]
	p64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return 0
	}
	return int(p64)
}
