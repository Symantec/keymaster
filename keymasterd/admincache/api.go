// Package admin cache caches admin credentials
package admincache

import (
	"sync"
	"time"
)

// Cache caches admin credentials
type Cache struct {
	clock       clock
	maxDuration time.Duration
	mu          sync.Mutex
	data        map[string]cacheEntry
}

// New creates a new cache that expires entries older than maxDuration.
func New(maxDuration time.Duration) *Cache {
	return newForTesting(maxDuration, kSystemClock)
}

// Get returns cached admin credentials for given user. isAdmin is true
// if user has admin credentials. valid is true if cache entry for user has
// not expired.  Initially, Get returns false, false for all users.
// If c is nil, Get always returns false, false
func (c *Cache) Get(user string) (isAdmin, valid bool) {
	return c.get(user)
}

// Put replaces admin credentials for given user. Admin credentials for user
// will remain valid for maxDuration time. If c is nil, Put is a no-op.
func (c *Cache) Put(user string, isAdmin bool) {
	c.put(user, isAdmin)
}
