package response

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// The quarantine path comes from the server verbatim. Quarantine moves a file
// away and leaves nothing behind, so an unconstrained handler hands whoever is
// on the other end of the connection a way to break the host or disable the
// agent.
func TestProtectedPathsCannotBeQuarantined(t *testing.T) {
	for _, p := range []string{
		"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config",
		"/bin/sh", "/usr/bin/sudo", "/etc/edr-agent/config.yml",
	} {
		if reason := protectedPathReason(p); reason == "" {
			t.Errorf("%s is not protected", p)
		}
	}
}

func TestTheAgentsOwnInstallationIsProtected(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot resolve own path: %v", err)
	}
	if reason := protectedPathReason(self); reason == "" {
		t.Error("the agent would quarantine its own binary")
	}
}

func TestAnOrdinaryFileIsNotProtected(t *testing.T) {
	// The denylist must not be so broad that quarantine stops working.
	for _, p := range []string{"/tmp/malware.bin", "/home/user/Downloads/x.exe", "/var/tmp/dropper"} {
		if reason := protectedPathReason(p); reason != "" {
			t.Errorf("%s was refused: %s", p, reason)
		}
	}
}

func TestPrefixMatchingRespectsPathBoundaries(t *testing.T) {
	// /etc/ssh is protected; /etc/sshd-something is a different path and must
	// not be caught by a bare string prefix.
	if protectedPathReason("/etc/sshd_other/file") != "" {
		t.Error("boundary-less prefix match refused an unrelated path")
	}
	if protectedPathReason("/etc/ssh/ssh_config") == "" {
		t.Error("a file inside a protected directory was allowed")
	}
}

func TestASymlinkIsRefusedRatherThanFollowed(t *testing.T) {
	// os.Stat follows symlinks, so a link pointing at a protected file would be
	// quarantined as though it were the link.
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	h, err := NewFileHandler(zap.NewNop(), filepath.Join(dir, "quarantine"), nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	_, err = h.Execute(context.Background(), map[string]interface{}{"path": link})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v; want the symlink refused", err)
	}
	if _, statErr := os.Lstat(link); statErr != nil {
		t.Error("the symlink was moved despite being refused")
	}
}
