package fusefrontend

import (
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// SharedStorageLock conveniently wraps F_OFD_SETLKW.
// It is a no-op unless args.SharedStorage is set.
//
// See https://man7.org/linux/man-pages/man2/fcntl.2.html -> "Open file description locks (non-POSIX)"
//
// lkType is one of:
// * unix.F_RDLCK (shared read lock)
// * unix.F_WRLCK (exclusive write lock)
// * unix.F_UNLCK (unlock)
//
// This function is a no-op if args.SharedStorage == false.
func (f *File) LockSharedStorage(lkType int16, lkStart int64, lkLen int64) (err error) {
	if !f.rootNode.args.SharedStorage {
		return nil
	}
	lk := unix.Flock_t{
		Type:   lkType,
		Whence: unix.SEEK_SET,
		Start:  lkStart,
		Len:    lkLen,
	}
	err = unix.FcntlFlock(uintptr(f.intFd()), syscallcompat.F_OFD_SETLK, &lk)
	switch err {
	case unix.EACCES, unix.EAGAIN:
		tlog.Debug.Printf("LockSharedStorage: waiting for lock")
	case nil:
		return
	}
	for {
		err = unix.FcntlFlock(uintptr(f.intFd()), syscallcompat.F_OFD_SETLKW, &lk)
		if err == unix.EINTR {
			tlog.Debug.Printf("LockSharedStorage: looping on EINTR")
			continue
		}
		return
	}
}

// UnlockSharedStorage calls LockSharedStorage with unix.F_UNLCK.
func (f *File) UnlockSharedStorage(lkStart int64, lkLen int64) error {
	return f.LockSharedStorage(unix.F_UNLCK, lkStart, lkLen)
}
