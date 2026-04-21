package collector

import (
	"os/user"
	"sync"
)

// UsernameCache resolves numeric UIDs to names with a small in-memory cache.
type UsernameCache struct {
	mu   sync.RWMutex
	uid  map[string]string
}

func NewUsernameCache() *UsernameCache {
	return &UsernameCache{uid: make(map[string]string)}
}

// Lookup returns the username for a UID string (e.g. "1000") or empty on failure.
func (c *UsernameCache) Lookup(uid string) string {
	if uid == "" {
		return ""
	}
	c.mu.RLock()
	if v, ok := c.uid[uid]; ok {
		c.mu.RUnlock()
		return v
	}
	c.mu.RUnlock()

	u, err := user.LookupId(uid)
	if err != nil || u == nil {
		return ""
	}
	name := u.Username
	c.mu.Lock()
	c.uid[uid] = name
	c.mu.Unlock()
	return name
}

// Invalidate clears cached UID→username mappings (e.g. after /etc/passwd changes).
func (c *UsernameCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.uid = make(map[string]string)
	c.mu.Unlock()
}
