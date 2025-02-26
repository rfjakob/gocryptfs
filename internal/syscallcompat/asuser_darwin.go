package syscallcompat

import (
	"runtime"
	"syscall"

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

	err := pthread_setugid_np(context.Owner.Uid, context.Owner.Gid)
	if err != nil {
		return -1, err
	}

	const (
		// KAUTH_UID_NONE and KAUTH_GID_NONE are special values to
		// revert permissions to the process credentials.
		KAUTH_UID_NONE = ^uint32(0) - 100
		KAUTH_GID_NONE = ^uint32(0) - 100
	)

	defer pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE)

	return f()
}

// Unfortunately pthread_setugid_np does not have a syscall wrapper yet.
func pthread_setugid_np(uid uint32, gid uint32) (err error) {
	_, _, e1 := syscall.RawSyscall(syscall.SYS_SETTID, uintptr(uid), uintptr(gid), 0)
	if e1 != 0 {
		err = e1
	}
	return
}
