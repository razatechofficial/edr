package selfprotect

import "testing"

// The signer records the path it was given at build time — dist/linux-amd64/
// edr-agent — while the checker runs against the installed absolute path.
// Matching only exactly meant every entry missed and nothing was ever verified,
// with a Warn as the only trace.
func TestAManifestEntryMatchesTheInstalledPath(t *testing.T) {
	files := map[string]string{
		"dist/linux-amd64/edr-agent": "abc123",
	}
	key, hash, ok := matchManifestEntry(files, "/usr/bin/edr-agent")
	if !ok {
		t.Fatal("the installed binary did not match its manifest entry")
	}
	if key != "dist/linux-amd64/edr-agent" || hash != "abc123" {
		t.Errorf("matched %q -> %q", key, hash)
	}
}

func TestAnExactMatchIsPreferred(t *testing.T) {
	files := map[string]string{
		"/usr/bin/edr-agent":         "exact",
		"dist/linux-amd64/edr-agent": "built",
	}
	_, hash, ok := matchManifestEntry(files, "/usr/bin/edr-agent")
	if !ok || hash != "exact" {
		t.Fatalf("hash = %q, want the exact entry", hash)
	}
}

// Verifying the wrong file against the right hash would report integrity it had
// not checked, so an ambiguous base name is refused rather than guessed.
func TestAnAmbiguousBaseNameIsRefused(t *testing.T) {
	files := map[string]string{
		"build/a/edr-agent": "one",
		"build/b/edr-agent": "two",
	}
	if _, _, ok := matchManifestEntry(files, "/usr/bin/edr-agent"); ok {
		t.Fatal("an ambiguous base name was matched")
	}
}

func TestAnUnknownFileDoesNotMatch(t *testing.T) {
	files := map[string]string{"dist/edr-agent": "abc"}
	if _, _, ok := matchManifestEntry(files, "/usr/bin/something-else"); ok {
		t.Fatal("an unrelated path matched")
	}
	if _, _, ok := matchManifestEntry(nil, "/usr/bin/edr-agent"); ok {
		t.Fatal("an empty manifest matched")
	}
}

// A release build must be able to refuse the disk baseline entirely. Baselining
// from disk trusts whatever is on it, so a binary replaced before first start
// becomes the baseline — the install-time tamper the mechanism exists to catch.
func TestTheSignedManifestRequirementDefaultsOffAndIsSettable(t *testing.T) {
	if RequireSignedManifest() {
		t.Error("the requirement defaults on; development builds would not start")
	}
	original := requireSignedManifestFlag
	t.Cleanup(func() { requireSignedManifestFlag = original })

	// The linker only sets strings, so the flag has to parse one. Anything
	// unrecognised must leave the requirement off rather than on, so a typo in
	// a build script cannot stop every agent starting.
	for _, on := range []string{"true", "TRUE", " 1 ", "yes", "on"} {
		requireSignedManifestFlag = on
		if !RequireSignedManifest() {
			t.Errorf("%q did not enable the requirement", on)
		}
	}
	for _, off := range []string{"", "false", "0", "no", "maybe", "ture"} {
		requireSignedManifestFlag = off
		if RequireSignedManifest() {
			t.Errorf("%q enabled the requirement", off)
		}
	}
}
