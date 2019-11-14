package admincache

import (
	"testing"
	"time"
)

type testClockType struct {
	NowTime time.Time
}

func (t *testClockType) Now() time.Time {
	return t.NowTime
}

func (t *testClockType) Advance(d time.Duration) {
	t.NowTime = t.NowTime.Add(d)
}

func TestAPIBasic(t *testing.T) {
	var cache *Cache
	isAdmin, valid := cache.Get("user")
	if valid {
		t.Fatalf("should have been invalid")
	}
	if isAdmin {
		t.Fatalf("should have been non admin")
	}
	cache.Put("user", true)

	cache2 := New(time.Minute)
	cache2.Put("user2", true)
	isAdmin, valid = cache2.Get("user2")
	if !valid {
		t.Fatalf("should have been valid")
	}
	if !isAdmin {
		t.Fatalf("should have been admin")
	}
}

func TestExpiration(t *testing.T) {
	testClock := &testClockType{
		NowTime: time.Date(2018, 1, 9, 12, 34, 56, 0, time.Local),
	}
	cache := newForTesting(5*time.Minute, testClock)
	//initial cache should be invalid/false
	admin, valid := cache.Get("user")
	if valid {
		t.Fatalf("should have been invalid")
	}
	if admin {
		t.Fatalf("should have been non admin")
	}
	//Expire works as expected
	cache.Put("user1", false)
	cache.Put("user2", true)
	testClock.Advance(4 * time.Minute)
	admin, valid = cache.Get("user1")
	if !valid {
		t.Fatalf("should have been valid")
	}
	if admin {
		t.Fatalf("should have been non admin")
	}

	admin, valid = cache.Get("user2")
	if !valid {
		t.Fatalf("should have been valid")
	}
	if !admin {
		t.Fatalf("should have been admin")
	}
	admin, valid = cache.Get("user")
	if valid {
		t.Fatalf("should have been invalid")
	}
	if admin {
		t.Fatalf("should have been non admin")
	}

	// This causes our two cache entries to expire
	// Because 5 minutes will have elapsed
	testClock.Advance(time.Minute)
	admin, valid = cache.Get("user1")
	if valid {
		t.Fatalf("should have been invalid")
	}
	if admin {
		t.Fatalf("should have been non admin")
	}
	admin, valid = cache.Get("user2")
	if valid {
		t.Fatalf("should have been invalid")
	}
	if !admin {
		t.Fatalf("should have been  admin")
	}
}
