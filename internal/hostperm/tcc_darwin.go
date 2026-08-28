//go:build darwin

package hostperm

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const systemTCC = "/Library/Application Support/com.apple.TCC/TCC.db"

func tccFDAClients() ([]string, error) {
	var (
		all       []string
		seen      = map[string]bool{}
		last      error
		systemErr error
	)
	for _, db := range tccDatabasePaths() {
		clients, err := queryTCCFile(db)
		if db == systemTCC {
			systemErr = err
		}
		if err != nil {
			last = err
			continue
		}
		for _, c := range clients {
			if seen[c] {
				continue
			}
			seen[c] = true
			all = append(all, c)
		}
	}
	if sensorTCCGranted(all) {
		return all, nil
	}
	if systemErr != nil {
		return all, systemErr
	}
	if len(all) > 0 {
		return all, nil
	}
	return nil, last
}

func tccDatabasePaths() []string {
	paths := []string{systemTCC}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, "Library/Application Support/com.apple.TCC/TCC.db"))
	}
	return paths
}

func queryTCCFile(db string) ([]string, error) {
	raw, err := os.ReadFile(db)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "edr-tcc-*.db")
	if err != nil {
		return nil, err
	}
	name := tmp.Name()
	defer func() {
		_ = os.Remove(name)
		_ = os.Remove(name + "-wal")
		_ = os.Remove(name + "-shm")
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	for _, suf := range []string{"-wal", "-shm"} {
		extra, err := os.ReadFile(db + suf)
		if err != nil {
			continue
		}
		_ = os.WriteFile(name+suf, extra, 0o600)
	}
	queries := []string{
		"SELECT client, auth_value FROM access WHERE service='kTCCServiceSystemPolicyAllFiles';",
		"SELECT client, auth_value FROM access WHERE service LIKE '%AllFiles%';",
		"SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles';",
		"SELECT client FROM access WHERE service LIKE '%AllFiles%';",
	}
	var (
		clients []string
		last    error
	)
	for _, q := range queries {
		out, err := runOutput(3*time.Second, "/usr/bin/sqlite3", "-separator", "|", name, q)
		if err != nil {
			last = err
			continue
		}
		parsed := parseTCCClientRows(out)
		if len(parsed) == 0 {
			continue
		}
		clients = parsed
		break
	}
	wal, _ := os.ReadFile(db + "-wal")
	if tccRawGrantsSensor(raw) || tccRawGrantsSensor(wal) {
		if !sensorTCCGranted(clients) {
			clients = append(clients, "edr-agent")
		}
	}
	if len(clients) > 0 {
		return clients, nil
	}
	if last != nil {
		return nil, last
	}
	return clients, nil
}

func evaluateFDAViaHelper() (Item, bool) {
	if os.Getenv("EDR_TCC_HELPER") == "1" {
		return Item{}, false
	}
	for _, bin := range edrctlCandidates() {
		cmd := exec.Command(bin, "hostperm")
		cmd.Env = append(os.Environ(), "EDR_TCC_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		var r Report
		if json.Unmarshal(extractJSONObject(out), &r) != nil {
			continue
		}
		for _, it := range r.Items {
			if it.ID == IDFDA {
				return it, true
			}
		}
	}
	return Item{}, false
}

func edrctlCandidates() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add("/usr/local/bin/edrctl")
	add("/Library/Application Support/EDR/bin/edrctl")
	add("/Applications/EDR Agent.app/Contents/MacOS/edrctl")
	add("/Applications/edr.app/Contents/MacOS/edr")
	if prog := launchdSensorProgram(); prog != "" {
		add(filepath.Join(filepath.Dir(prog), "edrctl"))
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Join(filepath.Dir(exe), "edrctl"))
	}
	return out
}

func extractJSONObject(b []byte) []byte {
	i := bytes.IndexByte(b, '{')
	j := bytes.LastIndexByte(b, '}')
	if i >= 0 && j > i {
		return b[i : j+1]
	}
	return b
}
