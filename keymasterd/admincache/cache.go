package admincache

import (
	"time"
)

type clock interface {
	Now() time.Time
}

type systemClockType struct{}

func (s systemClockType) Now() time.Time {
	return time.Now()
}

var (
	kSystemClock systemClockType
)

type cacheEntry struct {
	IsAdmin bool
	Ts      time.Time
}

func newForTesting(maxDuration time.Duration, clock clock) *Cache {
	return &Cache{
		data:        make(map[string]cacheEntry),
		clock:       clock,
		maxDuration: maxDuration}
}

func (c *Cache) get(user string) (isAdmin, valid bool) {
	if c == nil {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.data[user]
	return entry.IsAdmin, c.isValid(entry.Ts)
}

func (c *Cache) put(user string, isAdmin bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[user] = cacheEntry{IsAdmin: isAdmin, Ts: c.clock.Now()}
}

func (c *Cache) isValid(ts time.Time) bool {
	if ts.IsZero() {
		return false
	}
	return c.clock.Now().Sub(ts) < c.maxDuration
}
