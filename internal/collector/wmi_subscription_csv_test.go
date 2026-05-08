package collector

import "testing"

func TestParseWMICsvKV(t *testing.T) {
	header := `"__Class","Name","CommandLineTemplate"`
	data := `"__EventConsumer","Cons1","C:/Windows/System32/cmd.exe"`
	m, err := ParseWMICsvKV(header, data)
	if err != nil {
		t.Fatal(err)
	}
	if m["Name"] != "Cons1" {
		t.Fatalf("Name: %q", m["Name"])
	}
	if m["CommandLineTemplate"] != `C:/Windows/System32/cmd.exe` {
		t.Fatalf("cmd: %q", m["CommandLineTemplate"])
	}
}

func TestMergeWMIPsCSVBlocks(t *testing.T) {
	if got := MergeWMIPsCSVBlocks("  a\nb  "); got != "a\nb" {
		t.Fatalf("got %q", got)
	}
}
