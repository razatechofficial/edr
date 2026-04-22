package detection

import (
	"strings"
	"testing"
	"time"
)

func TestContainerCorrelatorNamespaceEscape(t *testing.T) {
	c := NewContainerCorrelator()
	now := time.Now().UTC()
	c.ObserveUnshare(123, "evil", cloneNewNS|cloneNewPID, now)
	c.ObserveMount(123, now.Add(time.Second))
	c.ObserveCapSysAdmin(123, true)
	out := c.Correlate()
	if len(out) != 1 || !strings.Contains(out[0], "namespace_escape:123:evil") {
		t.Fatalf("unexpected correlation: %#v", out)
	}
}
