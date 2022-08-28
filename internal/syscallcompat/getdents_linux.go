//go:build linux
// +build linux

package syscallcompat

// Other implementations of getdents in Go:
// https://github.com/ericlagergren/go-gnulib/blob/cb7a6e136427e242099b2c29d661016c19458801/dirent/getdents_unix.go
// https://github.com/golang/tools/blob/5831d16d18029819d39f99bdc2060b8eff410b6b/imports/fastwalk_unix.go

import (
	"bytes"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const sizeofDirent = int(unsafe.Sizeof(unix.Dirent{}))

// maxReclen sanity check: Reclen should never be larger than this.
// Due to padding between entries, it is 280 even on 32-bit architectures.
// See https://github.com/rfjakob/gocryptfs/issues/197 for details.
const maxReclen = 280

// getdents wraps unix.Getdents and converts the result to []fuse.DirEntry.
func getdents(fd int) (entries []fuse.DirEntry, entriesSpecial []fuse.DirEntry, err error) {
	// Collect syscall result in smartBuf.
	// "bytes.Buffer" is smart about expanding the capacity and avoids the
	// exponential runtime of simple append().
	var smartBuf bytes.Buffer
	tmp := make([]byte, 10000)
	for {
		n, err := unix.Getdents(fd, tmp)
		// unix.Getdents has been observed to return EINTR on cifs mounts
		if err == unix.EINTR {
			if n > 0 {
				smartBuf.Write(tmp[:n])
			}
			continue
		} else if err != nil {
			if smartBuf.Len() > 0 {
				tlog.Warn.Printf("warning: unix.Getdents returned errno %d in the middle of data ( https://github.com/rfjakob/gocryptfs/issues/483 )", err.(syscall.Errno))
				return nil, nil, syscall.EIO
			}
			return nil, nil, err
		}
		if n == 0 {
			break
		}
		smartBuf.Write(tmp[:n])
	}
	// Make sure we have at least Sizeof(Dirent) of zeros after the last
	// entry. This prevents a cast to Dirent from reading past the buffer.
	smartBuf.Grow(sizeofDirent)
	buf := smartBuf.Bytes()
	// Count the number of directory entries in the buffer so we can allocate
	// a fuse.DirEntry slice of the correct size at once.
	var numEntries, offset int
	for offset < len(buf) {
		s := *(*unix.Dirent)(unsafe.Pointer(&buf[offset]))
		if s.Reclen == 0 {
			tlog.Warn.Printf("Getdents: corrupt entry #%d: Reclen=0 at offset=%d. Returning EBADR",
				numEntries, offset)
			// EBADR = Invalid request descriptor
			return nil, nil, syscall.EBADR
		}
		if int(s.Reclen) > maxReclen {
			tlog.Warn.Printf("Getdents: corrupt entry #%d: Reclen=%d > %d. Returning EBADR",
				numEntries, s.Reclen, maxReclen)
			return nil, nil, syscall.EBADR
		}
		offset += int(s.Reclen)
		numEntries++
	}
	// Parse the buffer into entries.
	// Note: syscall.ParseDirent() only returns the names,
	// we want all the data, so we have to implement
	// it on our own.
	entries = make([]fuse.DirEntry, 0, numEntries)
	offset = 0
	for offset < len(buf) {
		s := *(*unix.Dirent)(unsafe.Pointer(&buf[offset]))
		name, err := getdentsName(s)
		if err != nil {
			return nil, nil, err
		}
		offset += int(s.Reclen)
		if name == "." || name == ".." {
			// These are always directories, no need to call convertDType.
			entriesSpecial = append(entriesSpecial, fuse.DirEntry{
				Ino:  s.Ino,
				Mode: syscall.S_IFDIR,
				Name: name,
			})
			continue
		}
		mode, err := convertDType(fd, name, s.Type)
		if err != nil {
			// The file may have been deleted in the meantime. Just skip it
			// and go on.
			continue
		}
		entries = append(entries, fuse.DirEntry{
			Ino:  s.Ino,
			Mode: mode,
			Name: name,
		})
	}
	return entries, entriesSpecial, nil
}

// getdentsName extracts the filename from a Dirent struct and returns it as
// a Go string.
func getdentsName(s unix.Dirent) (string, error) {
	// After the loop, l contains the index of the first '\0'.
	l := 0
	for l = range s.Name {
		if s.Name[l] == 0 {
			break
		}
	}
	if l < 1 {
		tlog.Warn.Printf("Getdents: invalid name length l=%d. Returning EBADR", l)
		// EBADR = Invalid request descriptor
		return "", syscall.EBADR
	}
	// Copy to byte slice.
	name := make([]byte, l)
	for i := range name {
		name[i] = byte(s.Name[i])
	}
	return string(name), nil
}

var dtUnknownWarnOnce sync.Once

func dtUnknownWarn(dirfd int) {
	const XFS_SUPER_MAGIC = 0x58465342 // From man 2 statfs
	var buf syscall.Statfs_t
	err := syscall.Fstatfs(dirfd, &buf)
	if err == nil && buf.Type == XFS_SUPER_MAGIC {
		// Old XFS filesystems always return DT_UNKNOWN. Downgrade the message
		// to "info" level if we are on XFS.
		// https://github.com/rfjakob/gocryptfs/issues/267
		tlog.Info.Printf("Getdents: convertDType: received DT_UNKNOWN, fstype=xfs, falling back to stat")
	} else {
		tlog.Warn.Printf("Getdents: convertDType: received DT_UNKNOWN, fstype=%#x, falling back to stat",
			buf.Type)
	}
}

// convertDType converts a Dirent.Type to at Stat_t.Mode value.
func convertDType(dirfd int, name string, dtype uint8) (uint32, error) {
	if dtype != syscall.DT_UNKNOWN {
		// Shift up by four octal digits = 12 bits
		return uint32(dtype) << 12, nil
	}
	// DT_UNKNOWN: we have to call stat()
	dtUnknownWarnOnce.Do(func() { dtUnknownWarn(dirfd) })
	var st unix.Stat_t
	err := Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return 0, err
	}
	// The S_IFMT bit mask extracts the file type from the mode.
	return st.Mode & syscall.S_IFMT, nil
}
