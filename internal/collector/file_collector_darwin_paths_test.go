//go:build darwin

package collector

import "testing"

func TestDefaultFIMPathsIncludeKeychainAndTCC(t *testing.T) {
	paths := DefaultFIMPaths()
	var hasKeychain, hasTCC bool
	for _, p := range paths {
		if p == "/Library/Keychains" {
			hasKeychain = true
		}
		if p == "/Library/Application Support/com.apple.TCC" {
			hasTCC = true
		}
	}
	if !hasKeychain || !hasTCC {
		t.Fatalf("darwin defaults missing paths: keychain=%v tcc=%v", hasKeychain, hasTCC)
	}
}
