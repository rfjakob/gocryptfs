package syscallcompat

import (
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// FS_NOCOW_FL is the flag set by "chattr +C" to disable copy-on-write on
// btrfs. Not exported by golang.org/x/sys/unix, value from linux/fs.h.
const FS_NOCOW_FL = 0x00800000

// dirHasNoCow checks whether the directory at the given path has the
// NOCOW (No Copy-on-Write) attribute set (i.e. "chattr +C").
// When a directory has this attribute, files created within it inherit
// NOCOW, which makes fallocate work correctly on btrfs because writes
// go in-place rather than through COW.
func dirHasNoCow(path string) bool {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		tlog.Debug.Printf("dirHasNoCow: Open %q failed: %v", path, err)
		return false
	}
	defer syscall.Close(fd)

	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		tlog.Debug.Printf("dirHasNoCow: FS_IOC_GETFLAGS on %q failed: %v", path, err)
		return false
	}
	return flags&FS_NOCOW_FL != 0
}

// DetectQuirks decides if there are known quirks on the backing filesystem
// that need to be workarounded.
//
// Tested by tests/root_test.TestBtrfsQuirks
func DetectQuirks(cipherdir string) (q uint64) {
	var st unix.Statfs_t
	err := unix.Statfs(cipherdir, &st)
	if err != nil {
		tlog.Warn.Printf("DetectQuirks: Statfs on %q failed: %v", cipherdir, err)
		return 0
	}

	// Preallocation on Btrfs is broken ( https://github.com/rfjakob/gocryptfs/issues/395 )
	// and slow ( https://github.com/rfjakob/gocryptfs/issues/63 ).
	//
	// The root cause is that btrfs COW allocates new blocks on write even for
	// preallocated extents, defeating the purpose of fallocate. However, if the
	// backing directory has the NOCOW attribute (chattr +C), writes go in-place
	// and fallocate works correctly.
	//
	// Cast to uint32 avoids compile error on arm: "constant 2435016766 overflows int32"
	if uint32(st.Type) == unix.BTRFS_SUPER_MAGIC {
		if dirHasNoCow(cipherdir) {
			tlog.Debug.Printf("DetectQuirks: Btrfs detected but cipherdir has NOCOW attribute (chattr +C), fallocate should work correctly")
		} else {
			// LogQuirk is called in fusefrontend/root_node.go
			q |= QuirkBtrfsBrokenFalloc
		}
	}

	return q
}
