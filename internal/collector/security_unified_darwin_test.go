//go:build darwin

package collector

import "testing"

func TestParseDarwinSecurityLogLine(t *testing.T) {
	t.Parallel()
	line := []byte(`{"subsystem":"com.apple.TCC","category":"access","eventMessage":"access denied kTCCServiceMicrophone"}`)
	ev, ok := parseDarwinSecurityLogLine(line, "ep1", "host1")
	if !ok {
		t.Fatal("expected parse ok")
	}
	if ev.Subsystem != "com.apple.TCC" {
		t.Fatalf("subsystem=%q", ev.Subsystem)
	}
	if ev.Message == "" {
		t.Fatal("expected message")
	}
	if ev.Category != "access" {
		t.Fatalf("category=%q", ev.Category)
	}
	if ev.AuthType != "tcc" {
		t.Fatalf("auth_type=%q", ev.AuthType)
	}
}

func TestParseDarwinSecurityLogLineRejectsEmpty(t *testing.T) {
	t.Parallel()
	_, ok := parseDarwinSecurityLogLine([]byte(`{"subsystem":"com.apple.sudo"}`), "e", "h")
	if ok {
		t.Fatal("expected reject without message")
	}
}

func TestDarwinSecurityLogPredicateIncludesTCC(t *testing.T) {
	t.Parallel()
	p := darwinSecurityLogPredicate()
	if !containsAll(p, `com.apple.TCC`, `com.apple.sudo`, `com.apple.xpc`) {
		t.Fatalf("predicate missing subsystems: %s", p)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !containsStr(s, p) {
			return false
		}
	}
	return true
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
