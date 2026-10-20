package rules

// Binds the MITRE mapper to the rule corpus it has to serve.
//
// The mapper's technique table used to be checked only against a handful of
// hand-picked IDs in mitre_test.go, all of which it knew. Meanwhile 113 of the
// 216 distinct technique tags across rules/sigma named techniques the table had
// never heard of, MapSigmaTag returned nil for every one of them, and the
// alerts those rules produced shipped with an empty MITRE slice — no technique
// for the console to attribute, nothing for the dedup key, and nothing for the
// validation suite, which matches detections on TechniqueID.
//
// Checking against the real corpus is the only assertion that could have
// caught that, because the defect was not in the mapper's logic: the logic did
// exactly what it was written to do for every input anybody had tested it
// with.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// sigmaCorpusDir is the shipped Sigma rule tree, relative to this package.
func sigmaCorpusDir() string {
	return filepath.Join("..", "..", "..", "rules", "sigma")
}

// The character class allows hyphens because the corpus contains both
// "attack.privilege_escalation" and "attack.privilege-escalation". Leaving
// hyphens out made this test silently skip the rules that used them, which is
// exactly the set most likely to be mis-mapped.
var reAttackTagLine = regexp.MustCompile(`(?m)^\s*-\s*(attack\.[A-Za-z0-9_.-]+)\s*$`)

type sigmaCorpusRule struct {
	path string
	tags []string
}

// loadSigmaCorpusTags reads every rule file and returns its attack tags.
//
// The tags are pulled with a regexp rather than a YAML parse on purpose: this
// test is about the mapper, and a YAML schema change in the rule files should
// fail the rule loader's own tests, not silently empty this one. The guard
// against that is the rule count assertion in the caller.
func loadSigmaCorpusTags(t *testing.T) []sigmaCorpusRule {
	t.Helper()

	var out []sigmaCorpusRule
	err := filepath.Walk(sigmaCorpusDir(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		var tags []string
		for _, m := range reAttackTagLine.FindAllStringSubmatch(string(raw), -1) {
			tags = append(tags, m[1])
		}
		out = append(out, sigmaCorpusRule{path: path, tags: tags})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", sigmaCorpusDir(), err)
	}
	return out
}

// TestSigmaCorpusEveryRuleCarriesAttackTags asserts no shipped rule is
// untagged.
//
// A rule with no attack tag cannot be attributed at all, however good the
// mapper is, and nine macOS unified-log and ESF rules were in that state: they
// fired, and the alert reached the console with an empty MITRE slice, which
// reads identically to a mapper failure. Untagged is the one case the mapper
// cannot compensate for, so it is asserted separately.
func TestSigmaCorpusEveryRuleCarriesAttackTags(t *testing.T) {
	var untagged []string
	for _, r := range loadSigmaCorpusTags(t) {
		if len(r.tags) == 0 {
			untagged = append(untagged, r.path)
		}
	}
	if len(untagged) > 0 {
		t.Errorf("%d rule files carry no attack.* tag:\n  %s\n"+
			"Add at least the ATT&CK tactic and, where there is one, the technique. An alert with no attribution cannot be triaged by technique or counted towards coverage.",
			len(untagged), strings.Join(untagged, "\n  "))
	}
}

// TestSigmaCorpusTagsAllMapToTechniques asserts every technique tag in the
// shipped rules resolves to a technique ID, a name and a tactic.
func TestSigmaCorpusTagsAllMapToTechniques(t *testing.T) {
	m := NewMITREMapper()
	rules := loadSigmaCorpusTags(t)

	// The corpus had 326 rule files when this was written. A collapse to a
	// handful means the walk or the tag regexp has stopped matching and
	// the test would pass vacuously.
	const minRules = 250
	if len(rules) < minRules {
		t.Fatalf("found %d tagged rules under %s, expected at least %d; the corpus walk or the tag pattern has stopped matching",
			len(rules), sigmaCorpusDir(), minRules)
	}

	techniqueTags := make(map[string]bool)
	for _, r := range rules {
		for _, tag := range r.tags {
			body := strings.ToLower(strings.TrimPrefix(tag, "attack."))
			if _, ok := canonicalTechniqueID(body); ok {
				techniqueTags[tag] = true
			}
		}
	}

	var noID, noName, noTactic []string
	for _, tag := range sortedTagList(techniqueTags) {
		mt := m.MapSigmaTag(tag)
		if mt == nil || mt.TechniqueID == "" {
			noID = append(noID, tag)
			continue
		}
		if mt.TechniqueName == "" {
			noName = append(noName, tag+" -> "+mt.TechniqueID)
		}
		if mt.TacticID == "" {
			noTactic = append(noTactic, tag+" -> "+mt.TechniqueID)
		}
	}

	t.Logf("%d tagged rules, %d distinct technique tags", len(rules), len(techniqueTags))

	if len(noID) > 0 {
		t.Errorf("%d technique tags map to no technique ID: %s\n"+
			"MapSigmaTag should report a well-formed technique ID whether or not initTechniques lists it; a nil result here means the tag is malformed or the fallback has been removed.",
			len(noID), strings.Join(noID, ", "))
	}
	if len(noName) > 0 {
		t.Errorf("%d technique tags map to an ID with no technique name:\n  %s\n"+
			"Add each to initTechniques with its ATT&CK name and primary tactic. An alert that names T1234 and not what T1234 is forces whoever reads it to go and look it up.",
			len(noName), strings.Join(noName, "\n  "))
	}
	if len(noTactic) > 0 {
		t.Errorf("%d technique tags map to an ID with no tactic:\n  %s\n"+
			"Either list the technique in initTechniques with its tactic, or give the rule an attack.<tactic> tag so MapSigmaTags can supply one.",
			len(noTactic), strings.Join(noTactic, "\n  "))
	}
}

// TestSigmaCorpusEveryRuleYieldsAttribution asserts that mapping a whole
// rule's tags produces at least one fully attributed entry.
//
// This is the per-rule view, and it catches what the per-tag view cannot: a
// rule whose technique is unlisted and which carries no tactic tag either, so
// that neither the table nor the rule can say which tactic it belongs to.
func TestSigmaCorpusEveryRuleYieldsAttribution(t *testing.T) {
	m := NewMITREMapper()
	rules := loadSigmaCorpusTags(t)

	var noMITRE, noTactic []string
	techniques := make(map[string]bool)
	for _, r := range rules {
		mapped := m.MapSigmaTags(r.tags)
		if len(mapped) == 0 {
			noMITRE = append(noMITRE, r.path)
			continue
		}
		for _, mt := range mapped {
			if mt.TechniqueID != "" {
				techniques[mt.TechniqueID] = true
			}
			if mt.TacticID == "" {
				noTactic = append(noTactic, r.path+" ("+mt.TechniqueID+")")
			}
		}
	}

	t.Logf("%d rules map to %d distinct techniques", len(rules), len(techniques))

	if len(noMITRE) > 0 {
		t.Errorf("%d rules produce no MITRE attribution at all:\n  %s",
			len(noMITRE), strings.Join(noMITRE, "\n  "))
	}
	if len(noTactic) > 0 {
		t.Errorf("%d rule/technique pairs produce a technique with no tactic:\n  %s\n"+
			"MapSigmaTags fills a missing tactic from the rule's own attack.<tactic> tag, so this means the technique is unlisted *and* the rule names no tactic. Fix either end.",
			len(noTactic), strings.Join(noTactic, "\n  "))
	}
}

// TestMITREMapperSubTechniqueInheritsParent asserts an unlisted sub-technique
// borrows its parent's name and tactic.
//
// ATT&CK sub-techniques always sit under their parent's tactic, so this is a
// property of the model rather than a convenience: it means a sub-technique
// added to a rule tomorrow is attributed to the right tactic today.
func TestMITREMapperSubTechniqueInheritsParent(t *testing.T) {
	t.Parallel()
	m := NewMITREMapper()

	// T1059 is listed; .999 is not a real sub-technique, which is the
	// point — nothing about this can be satisfied by adding a table entry.
	got := m.MapSigmaTag("attack.t1059.999")
	if got == nil {
		t.Fatal("MapSigmaTag returned nil for a well-formed sub-technique tag")
	}
	if got.TechniqueID != "T1059.999" {
		t.Errorf("TechniqueID = %q, want T1059.999", got.TechniqueID)
	}
	parent := m.MapTechnique("T1059")
	if parent == nil {
		t.Fatal("T1059 is no longer in the technique table; pick another listed parent for this test")
	}
	if got.TacticID != parent.TacticID {
		t.Errorf("TacticID = %q, want the parent's %q", got.TacticID, parent.TacticID)
	}
	if got.TechniqueName != parent.TechniqueName {
		t.Errorf("TechniqueName = %q, want the parent's %q", got.TechniqueName, parent.TechniqueName)
	}

	// An unlisted technique with no listed parent still yields its ID.
	orphan := m.MapSigmaTag("attack.t9999")
	if orphan == nil || orphan.TechniqueID != "T9999" {
		t.Errorf("MapSigmaTag(attack.t9999) = %+v, want a bare TechniqueID of T9999", orphan)
	}
}

// TestMapSigmaTagsFillsTacticFromRuleTag asserts the rule-level tactic tag
// supplies a tactic the technique table cannot.
func TestMapSigmaTagsFillsTacticFromRuleTag(t *testing.T) {
	t.Parallel()
	m := NewMITREMapper()

	got := m.MapSigmaTags([]string{"attack.persistence", "attack.t9998"})
	if len(got) != 1 {
		t.Fatalf("MapSigmaTags returned %d entries, want 1 (the technique, with the tactic folded in): %+v", len(got), got)
	}
	if got[0].TechniqueID != "T9998" {
		t.Errorf("TechniqueID = %q, want T9998", got[0].TechniqueID)
	}
	if got[0].TacticID != "TA0003" || got[0].TacticName != "Persistence" {
		t.Errorf("tactic = %q/%q, want TA0003/Persistence from the rule's attack.persistence tag", got[0].TacticID, got[0].TacticName)
	}

	// A rule that names only a tactic still gets attributed to it.
	only := m.MapSigmaTags([]string{"attack.impact"})
	if len(only) != 1 || only[0].TacticID != "TA0040" || only[0].TechniqueID != "" {
		t.Errorf("MapSigmaTags(attack.impact) = %+v, want one tactic-only entry for TA0040", only)
	}

	if got := m.MapSigmaTags(nil); len(got) != 0 {
		t.Errorf("MapSigmaTags(nil) = %+v, want no entries", got)
	}
}

func sortedTagList(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
