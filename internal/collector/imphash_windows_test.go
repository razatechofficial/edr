//go:build windows

package collector

import "testing"

func TestImpHashFromImportedSymbolsKnown(t *testing.T) {
	// Matches md5("kernel32.dll.exitprocess,user32.dll.messageboxa")
	syms := []string{"ExitProcess:KERNEL32.dll", "MessageBoxA:user32.dll"}
	got := impHashFromImportedSymbols(syms)
	want := "73867cd01e118b6e894450df7de99e12"
	if got != want {
		t.Fatalf("imphash got %q want %q", got, want)
	}
}

func TestImpHashFromImportedSymbolsEmpty(t *testing.T) {
	got := impHashFromImportedSymbols(nil)
	want := "d41d8cd98f00b204e9800998ecf8427e"
	if got != want {
		t.Fatalf("empty imphash got %q want %q", got, want)
	}
}
