//go:build darwin

package kernel

import "testing"

// TestEsfOperationNameFallback pins the es_event_type_t ordinals this table
// claims.
//
// The expectations are the ordinals in the SDK's own enum
// ($(xcrun --show-sdk-path)/usr/include/EndpointSecurity/ESTypes.h), which
// Apple only appends to. The previous version of this test asserted the
// table's own wrong numbers back to itself -- xpc_connect=65, tcc_modify=147,
// cs_invalidated=62 -- so it passed while every mapping was off, and an XPC
// connection was being reported as a TCC privacy authorization.
func TestEsfOperationNameFallback(t *testing.T) {
	t.Parallel()
	cases := map[int]string{
		96:  "cs_invalidated",
		105: "setuid",
		106: "setgid",
		109: "setreuid",
		114: "xp_malware_detected",
		147: "xpc_connect",
		149: "tcc_modify",
	}
	for raw, want := range cases {
		if got := esfOperationNameFallback(raw); got != want {
			t.Errorf("raw=%d got=%q want=%q", raw, got, want)
		}
	}
	// An ordinal nothing claims must stay unknown rather than borrowing a
	// neighbour's name.
	if got := esfOperationNameFallback(62); got != "unknown" {
		t.Errorf("raw=62 (NOTIFY_FCNTL) got=%q, want unknown", got)
	}
}
