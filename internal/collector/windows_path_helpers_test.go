package collector

import (
	"runtime"
	"testing"
)

func TestTrustedWinPath(t *testing.T) {
	sys := `c:\windows`
	pf := `c:\program files`
	if !trustedWinPath(`c:\windows\system32\foo.dll`, sys, pf) {
		t.Fatal("expected system32 under system root")
	}
	if !trustedWinPath(`c:\program files\app\x.exe`, sys, pf) {
		t.Fatal("expected PF prefix")
	}
	if trustedWinPath(`c:\users\mallory\bad.dll`, sys, pf) {
		t.Fatal("untrusted path should fail")
	}
}

func TestNormalizeWinPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("filepath.Clean for drive-letter paths is only canonical on Windows")
	}
	if g := normalizeWinPath(`  C:\FOO\bar\  `); g != `c:\foo\bar` {
		t.Fatalf("got %q", g)
	}
}
