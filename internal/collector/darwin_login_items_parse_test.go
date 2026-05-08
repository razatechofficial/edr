package collector

import (
	"reflect"
	"testing"
)

func TestSplitDarwinLoginItemPaths(t *testing.T) {
	raw := "/Applications/Foo.app\n, '/Applications/Bar.app'"
	got := splitDarwinLoginItemPaths(raw)
	want := []string{"/Applications/Foo.app", "/Applications/Bar.app"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if empty := splitDarwinLoginItemPaths(""); len(empty) != 0 {
		t.Fatalf("expected empty slice")
	}
}
