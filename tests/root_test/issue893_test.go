//go:build linux

package root_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// gocryptfs v2.5.0 upgraded x/sys/unix and we found out that, since
// https://github.com/golang/sys/commit/d0df966e6959f00dc1c74363e537872647352d51 ,
// unix.Setreuid() and friends now affect the whole process instead of only the
// current thread, breaking allow_other: https://github.com/rfjakob/gocryptfs/issues/893
//
// Let's not have this happen again by testing it here.
func TestConcurrentUserOps(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("must run as root")
	}

	var wg sync.WaitGroup

	oneStressor := func(tid int) {
		defer wg.Done()
		err := asUser(10000+tid, 20000+tid, nil, func() (err error) {
			for i := 0; i < 100; i++ {
				d := fmt.Sprintf("%s/tid%d.i%d/foo/bar/baz", test_helpers.DefaultPlainDir, tid, i)
				if err = os.MkdirAll(d, 0700); err != nil {
					return
				}
				if err = ioutil.WriteFile(d+"/foo", nil, 0400); err != nil {
					return
				}
				if err = ioutil.WriteFile(d+"/bar", []byte("aaaaaaaaaaaaaaaaaaaaa"), 0400); err != nil {
					return
				}
				if err = syscall.Unlink(d + "/foo"); err != nil {
					return
				}
				if err = os.Mkdir(d+"/foo", 0700); err != nil {
					return
				}
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	}

	threads := 4
	wg.Add(threads)
	for tid := 0; tid < threads; tid++ {
		go oneStressor(tid)
	}
	wg.Wait()
}

// Test that our root_test.asUser function works as expected under concurrency by
// similating a long-runnig operation with sleep(10ms).
// https://github.com/rfjakob/gocryptfs/issues/893
func TestAsUserSleep(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("must run as root")
	}

	var wg sync.WaitGroup
	f := func(euid_want int) error {
		euid_have := syscall.Geteuid()
		if euid_want != euid_have {
			return fmt.Errorf("wrong euid: want=%d have=%d", euid_want, euid_have)
		}
		time.Sleep(10 * time.Millisecond)
		euid_have2 := syscall.Geteuid()
		if euid_want != euid_have2 {
			return fmt.Errorf("wrong euid: want=%d have2=%d", euid_want, euid_have2)
		}
		return nil
	}
	threads := 100
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func(i int) {
			defer wg.Done()
			err := asUser(10000+i, 20000+i, nil, func() error { return f(10000 + i) })
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}
