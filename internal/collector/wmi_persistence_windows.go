//go:build windows

package collector

import (
	"encoding/json"
	"os/exec"
	"strings"
)

// WMIPersistenceSnapshot returns counts of WMI event filters/consumers/bindings (best-effort).
func WMIPersistenceSnapshot() map[string]any {
	ps := `
$ns = 'root/subscription'
try {
  $f = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop)
  $c = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop)
  $b = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop)
  '{"filters":' + $f.Count + ',"consumers":' + $c.Count + ',"bindings":' + $b.Count + '}'
} catch {
  $msg = $_.Exception.Message -replace '"',''''''
  '{"error":"' + $msg + '"}'
}
`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return map[string]any{"error": err.Error(), "detail": text}
	}
	var v struct {
		Filters   int    `json:"filters"`
		Consumers int    `json:"consumers"`
		Bindings  int    `json:"bindings"`
		Error     string `json:"error"`
	}
	if json.Unmarshal([]byte(text), &v) == nil {
		if v.Error != "" {
			return map[string]any{"error": v.Error}
		}
		return map[string]any{
			"filters":   v.Filters,
			"consumers": v.Consumers,
			"bindings":  v.Bindings,
		}
	}
	return map[string]any{"raw": text}
}
