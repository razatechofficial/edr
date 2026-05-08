package collector

import "testing"

func TestTCCRowChangeTag(t *testing.T) {
	if g, w := TCCRowChangeTag(false), "tcc_added"; g != w {
		t.Fatalf("new row: got %q want %q", g, w)
	}
	if g, w := TCCRowChangeTag(true), "tcc_modified"; g != w {
		t.Fatalf("modified row: got %q want %q", g, w)
	}
}
