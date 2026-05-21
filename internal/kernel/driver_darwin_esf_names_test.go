//go:build darwin

package kernel

import "testing"

func TestEsfOperationNameFallback(t *testing.T) {
	t.Parallel()
	cases := map[int]string{
		65:  "xpc_connect",
		147: "tcc_modify",
		62:  "cs_invalidated",
		112: "xp_malware_detected",
	}
	for raw, want := range cases {
		if got := esfOperationNameFallback(raw); got != want {
			t.Fatalf("raw=%d got=%q want=%q", raw, got, want)
		}
	}
}
