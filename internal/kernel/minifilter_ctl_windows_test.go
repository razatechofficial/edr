//go:build windows

package kernel

import "testing"

func TestClassifyFilterPortHR(t *testing.T) {
	t.Parallel()
	cases := []struct {
		hr        uint32
		wantClass string
	}{
		{0x800706BA, "transient"},
		{0x80070002, "permanent"},
		{0xDEADBEEF, "permanent"},
	}
	for _, tc := range cases {
		class, err := classifyFilterPortHR(tc.hr)
		if class != tc.wantClass {
			t.Fatalf("hr=%08x: class=%q want %q err=%v", tc.hr, class, tc.wantClass, err)
		}
		if err == nil {
			t.Fatalf("hr=%08x: expected error", tc.hr)
		}
	}
}
