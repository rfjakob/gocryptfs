package syscallcompat

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func fillDirEntries(fd int, names []string) ([]fuse.DirEntry, error) {
	out := make([]fuse.DirEntry, 0, len(names))
	for _, name := range names {
		var st unix.Stat_t
		err := Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == syscall.ENOENT {
			// File disappeared between readdir and stat. Pretend we did not
			// see it.
			continue
		}
		if err != nil {
			return nil, err
		}
		newEntry := fuse.DirEntry{
			Name: name,
			Mode: uint32(st.Mode) & syscall.S_IFMT,
			Ino:  st.Ino,
		}
		out = append(out, newEntry)
	}
	return out, nil
}

// emulateGetdents reads all directory entries from the open directory "fd"
// and returns normal entries and "." / ".." split into two slices.
func emulateGetdents(fd int) (out []fuse.DirEntry, outSpecial []fuse.DirEntry, err error) {
	// os.File closes the fd in its finalizer. Duplicate the fd to not affect
	// the original fd.
	newFd, err := syscall.Dup(fd)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(newFd), "")
	defer f.Close()
	// Get all file names in the directory
	names, err := f.Readdirnames(0)
	if err != nil {
		return nil, nil, err
	}
	// Stat all the names and convert to fuse.DirEntry
	out, err = fillDirEntries(fd, names)
	if err != nil {
		return nil, nil, err
	}
	outSpecial, err = fillDirEntries(fd, []string{".", ".."})
	if err != nil {
		return nil, nil, err
	}
	return out, outSpecial, nil
}
