package platform

import "testing"

func TestCurrentAndArch(t *testing.T) {
	t.Parallel()
	if Current() == "" {
		t.Fatalf("current OS type must not be empty")
	}
	if Arch() == "" {
		t.Fatalf("arch must not be empty")
	}
}

func TestPlatformPathsNotEmpty(t *testing.T) {
	t.Parallel()
	if DataDir() == "" || ConfigDir() == "" || LogDir() == "" || TempDir() == "" || RulesDir() == "" || QuarantineDir() == "" || PIDFile() == "" {
		t.Fatalf("platform path accessors must not return empty values")
	}
	if DataSubdir("ioc") == "" {
		t.Fatalf("datasubdir must not be empty")
	}
}
