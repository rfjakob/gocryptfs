//go:build (linux && 386) || (linux && arm)

package syscallcompat

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// See thread_credentials_linux.go for docs

// Setreuid is like setreuid(2) but affects only the current thread
func Setreuid(ruid int, euid int) (err error) {
	_, _, e1 := unix.RawSyscall(unix.SYS_SETREUID32, uintptr(ruid), uintptr(euid), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// Setreuid is like setregid(2) but affects only the current thread
func Setregid(rgid int, egid int) (err error) {
	_, _, e1 := unix.RawSyscall(unix.SYS_SETREGID32, uintptr(rgid), uintptr(egid), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func setgroups(n int, list *uint32) (err error) {
	_, _, e1 := unix.RawSyscall(unix.SYS_SETGROUPS32, uintptr(n), uintptr(unsafe.Pointer(list)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}
