package admincache

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
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

func TestAPI(t *testing.T) {
	Convey("nil cache", t, func() {
		var cache *Cache
		Convey("Get returns false, false", func() {
			admin, valid := cache.Get("user")
			So(admin, ShouldBeFalse)
			So(valid, ShouldBeFalse)
		})
		Convey("Put is a no-op", func() {
			cache.Put("user", true)
		})
	})
	Convey("API", t, func() {
		testClock := &testClockType{
			NowTime: time.Date(2018, 1, 9, 12, 34, 56, 0, time.Local),
		}
		cache := newForTesting(5*time.Minute, testClock)
		Convey("Initially cache returns false/invalid", func() {
			admin, valid := cache.Get("user")
			So(admin, ShouldBeFalse)
			So(valid, ShouldBeFalse)
		})
		Convey("Cache entries expire as expected", func() {
			cache.Put("user1", false)
			cache.Put("user2", true)

			testClock.Advance(4 * time.Minute)

			admin, valid := cache.Get("user1")
			So(admin, ShouldBeFalse)
			So(valid, ShouldBeTrue)
			admin, valid = cache.Get("user2")
			So(admin, ShouldBeTrue)
			So(valid, ShouldBeTrue)
			admin, valid = cache.Get("user")
			So(admin, ShouldBeFalse)
			So(valid, ShouldBeFalse)

			// This causes our two cache entries to expire
			// Because 5 minutes will have elapsed
			testClock.Advance(time.Minute)

			admin, valid = cache.Get("user1")
			So(admin, ShouldBeFalse)
			So(valid, ShouldBeFalse)
			admin, valid = cache.Get("user2")
			So(admin, ShouldBeTrue)
			So(valid, ShouldBeFalse)
		})
	})
}
