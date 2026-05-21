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
