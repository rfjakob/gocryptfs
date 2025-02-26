package syscallcompat

import (
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// asUser runs `f()` under the effective uid, gid, groups specified
// in `context`.
//
// If `context` is nil, `f()` is executed directly without switching user id.
func asUser(f func() (int, error), context *fuse.Context) (int, error) {
	if context == nil {
		return f()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Since go1.16beta1 (commit d1b1145cace8b968307f9311ff611e4bb810710c ,
	// https://go-review.googlesource.com/c/go/+/210639 )
	// syscall.{Setgroups,Setregid,Setreuid} affects all threads, which
	// is exactly what we not want.
	//
	// We now use unix.{Setgroups,Setregid,Setreuid} instead.

	err := unix.Setgroups(getSupplementaryGroups(context.Pid))
	if err != nil {
		return -1, err
	}
	defer unix.Setgroups(nil)

	err = unix.Setregid(-1, int(context.Owner.Gid))
	if err != nil {
		return -1, err
	}
	defer unix.Setregid(-1, 0)

	err = unix.Setreuid(-1, int(context.Owner.Uid))
	if err != nil {
		return -1, err
	}
	defer unix.Setreuid(-1, 0)

	return f()
}
