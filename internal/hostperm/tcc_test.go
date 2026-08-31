package hostperm

import "testing"

func TestProductTCCClient(t *testing.T) {
	yes := []string{
		"/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent",
		"/usr/local/libexec/edr-agent.app",
		"com.razatech.edr-agent",
		"com.razatech.edr.console",
		"/Library/Application Support/EDR/bin/edr-agent",
		"/Library/Application Support/EDR/bin/edr",
		"edr-agent",
		"edr-agent-ui",
		"edrctl",
		"edr",
		"/Applications/EDR Agent.app",
		"/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui",
		"/Applications/edr.app",
		"edr-agent-55554944560e2f9119a136c3d3008c04d26ae1f7",
	}
	for _, c := range yes {
		if !isProductTCCClient(c) {
			t.Fatalf("want product: %s", c)
		}
	}
	no := []string{"", "Safari", "com.apple.mail"}
	for _, c := range no {
		if isProductTCCClient(c) {
			t.Fatalf("want other: %s", c)
		}
	}
}

func TestSensorListedInTCC(t *testing.T) {
	sensor := "/Library/Application Support/EDR/bin/edr-agent"
	if sensorListedInTCC(nil, sensor) {
		t.Fatal("empty clients")
	}
	if sensorListedInTCC([]string{"/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui"}, sensor) {
		t.Fatal("console FDA must not satisfy the sensor")
	}
	if sensorListedInTCC([]string{"com.razatech.edr.console"}, sensor) {
		t.Fatal("console bundle must not satisfy the sensor")
	}
	if !sensorListedInTCC([]string{sensor}, sensor) {
		t.Fatal("exact sensor path")
	}
	if !sensorListedInTCC([]string{"edr-agent"}, sensor) {
		t.Fatal("basename")
	}
	if !sensorListedInTCC([]string{"com.razatech.edr-agent"}, sensor) {
		t.Fatal("bundle id")
	}
	if !sensorListedInTCC([]string{"/usr/local/libexec/edr-agent.app"}, sensor) {
		t.Fatal("sensor app bundle")
	}
}

func TestTccRawGrantsSensor(t *testing.T) {
	if tccRawGrantsSensor(nil) {
		t.Fatal("empty")
	}
	if !tccRawGrantsSensor([]byte("/Library/Application Support/EDR/bin/edr-agent\x00")) {
		t.Fatal("install path")
	}
	if !tccRawGrantsSensor([]byte("com.razatech.edr-agent")) {
		t.Fatal("bundle")
	}
	if !tccRawGrantsSensor([]byte("edr-agent-55554944560e2f9119a136c3d3008c04d26ae1f7")) {
		t.Fatal("adhoc")
	}
	if tccRawGrantsSensor([]byte("com.razatech.edr.console")) {
		t.Fatal("console bundle is not the sensor")
	}
	if tccRawGrantsSensor([]byte("EDR-Agent-Setup.app")) {
		t.Fatal("Setup.app is not the sensor")
	}
}

func TestConsoleOrSetupTCCClient(t *testing.T) {
	if !isConsoleOrSetupTCCClient("/Users/me/Downloads/EDR-Agent-Setup.app") {
		t.Fatal("setup app")
	}
	if isConsoleOrSetupTCCClient("/usr/local/libexec/edr-agent.app") {
		t.Fatal("sensor app is not setup")
	}
}
func TestProtectedReadLooksGranted(t *testing.T) {
	if protectedReadLooksGranted("reading config /x: open /x: operation not permitted") {
		t.Fatal("denied")
	}
	if !protectedReadLooksGranted("parsing config: yaml: unmarshal errors") {
		t.Fatal("opened")
	}
}

func TestParseTCCClientRows(t *testing.T) {
	got := parseTCCClientRows("com.razatech.edr-agent|2\nignored|0\nedr-agent|3\n")
	if len(got) != 2 || got[0] != "com.razatech.edr-agent" || got[1] != "edr-agent" {
		t.Fatalf("%v", got)
	}
}
