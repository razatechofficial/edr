//go:build darwin

package collector

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
)

// darwinLsofConnections uses `lsof -i -n -P -F pcfnTPn` to enumerate sockets
// with pid attribution. Shared idea with DarwinNetworkSource but keyed for the
// legacy NetworkCollector accumulator.
func darwinLsofConnections() []connEntry {
	cmd := exec.Command("lsof", "-i", "-n", "-P", "-F", "pcfTPn")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var (
		outEntries []connEntry
		pid        int
		proto      string
	)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 1 {
			continue
		}
		switch line[0] {
		case 'p':
			if v, err := strconv.Atoi(line[1:]); err == nil {
				pid = v
				proto = ""
			}
		case 'P':
			proto = strings.ToLower(line[1:])
		case 'n':
			srcIP, srcPort, dstIP, dstPort, ok := parseLsofConn(line[1:])
			if !ok {
				continue
			}
			outEntries = append(outEntries, connEntry{
				proto:   proto,
				srcIP:   srcIP,
				srcPort: srcPort,
				dstIP:   dstIP,
				dstPort: dstPort,
				pid:     pid,
			})
		}
	}
	return outEntries
}
