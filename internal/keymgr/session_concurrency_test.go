package keymgr

import (
	"sync"
	"testing"
	"time"
)

func TestConcurrentSessionLifecycleAccess(t *testing.T) {
	km := &keyMgr{
		sessions: map[string]session{
			"active": {expires: time.Now().Add(time.Minute)},
		},
		key: []byte("invalid-test-key"),
	}

	var workers sync.WaitGroup
	for i := 0; i < 100; i++ {
		workers.Add(1)
		go func(operation int) {
			defer workers.Done()
			switch operation % 3 {
			case 0:
				_, _, _ = km.RollToken("active")
			case 1:
				km.LogOut("missing")
			case 2:
				_, _, _, _ = km.MakeDelegate("test-pup", "active")
			}
		}(i)
	}
	workers.Wait()
}
