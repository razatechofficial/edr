package ocsf

import "testing"

func TestFromNetwork(t *testing.T) {
	t.Parallel()
	env := FromNetwork(NetworkInput{
		DestIP:   "10.0.0.5",
		DestPort: 443,
		SourceIP: "192.168.1.2",
		Protocol: "tcp",
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDNetworkActivity {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.DstEndpoint == nil || env.DstEndpoint.IP != "10.0.0.5" {
		t.Fatalf("dst=%v", env.DstEndpoint)
	}
}

func TestFromDNS(t *testing.T) {
	t.Parallel()
	env := FromDNS(NetworkInput{
		Domain:   "evil.example.com",
		Protocol: "dns",
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDDNSActivity {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Query == nil || env.Query.Hostname != "evil.example.com" {
		t.Fatalf("query=%v", env.Query)
	}
}

func TestFromNetworkDNSHeuristic(t *testing.T) {
	t.Parallel()
	env := FromNetwork(NetworkInput{Domain: "cdn.example.com"}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDDNSActivity {
		t.Fatalf("expected dns class, got %d", env.ClassUID)
	}
}

func TestFromScheduledJob(t *testing.T) {
	t.Parallel()
	env := FromScheduledJob(ScheduledJobInput{
		TaskName:  "DailyBackup",
		Operation: "Create",
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDScheduledJobActivity {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Job == nil || env.Job.Name != "DailyBackup" {
		t.Fatalf("job=%v", env.Job)
	}
}

func TestFromAuth(t *testing.T) {
	t.Parallel()
	env := FromAuth(AuthInput{
		User:     "admin",
		AuthType: "logon",
		Success:  false,
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDAuthentication {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Status != "Failure" {
		t.Fatalf("status=%q", env.Status)
	}
}

func TestFromRegistry(t *testing.T) {
	t.Parallel()
	env := FromRegistry(RegistryInput{
		KeyPath:   `HKLM\Software\Test`,
		Operation: "set",
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDRegistryKeyActivity {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
}

func TestFromFork(t *testing.T) {
	t.Parallel()
	env := FromFork(ForkInput{ParentPID: 1, ChildPID: 2}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDProcessActivity {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Process == nil || env.Process.ParentProcess == nil || env.Process.ParentProcess.PID != 1 {
		t.Fatalf("parent_process=%v", env.Process)
	}
}

func TestFromPrivilege(t *testing.T) {
	t.Parallel()
	env := FromPrivilege(PrivilegeInput{
		PID:       100,
		PPID:      1,
		Operation: "setuid",
		NewUID:    0,
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDProcessActivity {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Unmapped["privilege"] != true {
		t.Fatal("expected privilege marker")
	}
}

func TestFromInjection(t *testing.T) {
	t.Parallel()
	env := FromInjection(InjectionInput{SourcePID: 10, TargetPID: 20, Technique: "hollow"}, DefaultProduct("test"))
	if env.Unmapped["injection"] != true {
		t.Fatal("expected injection marker")
	}
}

func TestEnvelopeToMap(t *testing.T) {
	t.Parallel()
	m := EnvelopeToMap(FromProcess(ProcessInput{ProcessName: "a.exe"}, DefaultProduct("")))
	if m["class_uid"] == nil {
		t.Fatal("missing class_uid in map")
	}
}
