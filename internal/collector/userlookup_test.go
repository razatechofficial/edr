//go:build !windows

package collector

import "testing"

func TestUsernameCacheRootAndHit(t *testing.T) {
	c := NewUsernameCache()
	u := c.Lookup("0")
	if u == "" {
		t.Skip("no passwd mapping for uid 0")
	}
	if u2 := c.Lookup("0"); u2 != u {
		t.Fatalf("cache hit: first %q second %q", u, u2)
	}
	c.Invalidate()
	if u3 := c.Lookup("0"); u3 == "" {
		t.Fatal("expected re-lookup after invalidate")
	}
}
