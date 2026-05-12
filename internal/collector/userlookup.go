package collector

import (
	"container/list"
	"os/user"
	"sync"
	"time"
)

// UsernameCache resolves numeric UIDs to names with a bounded positive
// cache and a TTL'd negative cache (P1-18).
//
// Why both: a misbehaving caller (or an attacker spamming events with
// random UIDs) used to grow the cache unbounded, and every miss
// re-triggered an /etc/passwd lookup. Now positive results live in a
// 1024-entry LRU, negative results live in a 256-entry LRU with a
// 5-minute TTL, and Lookup returns the raw UID for unknown users (so
// downstream consumers see a stable string rather than empty).
type UsernameCache struct {
	mu       sync.Mutex
	positive *uidLRU
	negative *uidLRU
}

const (
	usernameCachePositiveMax = 1024
	usernameCacheNegativeMax = 256
	usernameCacheNegativeTTL = 5 * time.Minute
)

func NewUsernameCache() *UsernameCache {
	return &UsernameCache{
		positive: newUIDLRU(usernameCachePositiveMax, 0),
		negative: newUIDLRU(usernameCacheNegativeMax, usernameCacheNegativeTTL),
	}
}

// Lookup returns the username for a UID string (e.g. "1000"). For
// unknown UIDs it returns the raw UID itself so detection rules see a
// consistent string identifier instead of empty.
func (c *UsernameCache) Lookup(uid string) string {
	if uid == "" {
		return ""
	}
	c.mu.Lock()
	if v, ok := c.positive.get(uid); ok {
		c.mu.Unlock()
		return v
	}
	if _, ok := c.negative.get(uid); ok {
		c.mu.Unlock()
		return uid
	}
	c.mu.Unlock()

	u, err := user.LookupId(uid)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil || u == nil {
		c.negative.put(uid, "")
		return uid
	}
	c.positive.put(uid, u.Username)
	return u.Username
}

// Invalidate clears cached UID→username mappings (e.g. after /etc/passwd changes).
func (c *UsernameCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.positive = newUIDLRU(usernameCachePositiveMax, 0)
	c.negative = newUIDLRU(usernameCacheNegativeMax, usernameCacheNegativeTTL)
	c.mu.Unlock()
}

// uidLRU is a minimal LRU with optional TTL on entries. ttl == 0 means
// "no expiry, evict by capacity only". It is not safe for concurrent
// use — UsernameCache wraps it with a mutex.
type uidLRU struct {
	cap   int
	ttl   time.Duration
	list  *list.List
	items map[string]*list.Element
}

type uidLRUEntry struct {
	key       string
	value     string
	expiresAt time.Time
}

func newUIDLRU(capacity int, ttl time.Duration) *uidLRU {
	return &uidLRU{
		cap:   capacity,
		ttl:   ttl,
		list:  list.New(),
		items: make(map[string]*list.Element, capacity),
	}
}

func (l *uidLRU) get(key string) (string, bool) {
	el, ok := l.items[key]
	if !ok {
		return "", false
	}
	e := el.Value.(*uidLRUEntry)
	if l.ttl > 0 && time.Now().After(e.expiresAt) {
		l.list.Remove(el)
		delete(l.items, key)
		return "", false
	}
	l.list.MoveToFront(el)
	return e.value, true
}

func (l *uidLRU) put(key, value string) {
	if el, ok := l.items[key]; ok {
		e := el.Value.(*uidLRUEntry)
		e.value = value
		if l.ttl > 0 {
			e.expiresAt = time.Now().Add(l.ttl)
		}
		l.list.MoveToFront(el)
		return
	}
	for l.list.Len() >= l.cap {
		back := l.list.Back()
		if back == nil {
			break
		}
		e := back.Value.(*uidLRUEntry)
		delete(l.items, e.key)
		l.list.Remove(back)
	}
	entry := &uidLRUEntry{key: key, value: value}
	if l.ttl > 0 {
		entry.expiresAt = time.Now().Add(l.ttl)
	}
	el := l.list.PushFront(entry)
	l.items[key] = el
}
