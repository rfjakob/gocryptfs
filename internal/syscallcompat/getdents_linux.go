// +build linux

package syscallcompat

// Other implementations of getdents in Go:
// https://github.com/ericlagergren/go-gnulib/blob/cb7a6e136427e242099b2c29d661016c19458801/dirent/getdents_unix.go
// https://github.com/golang/tools/blob/5831d16d18029819d39f99bdc2060b8eff410b6b/imports/fastwalk_unix.go

import (
	"bytes"
	"syscall"
	"unsafe"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// HaveGetdents is true if we have a working implementation of Getdents
const HaveGetdents = true

const sizeofDirent = int(unsafe.Sizeof(syscall.Dirent{}))

// Getdents wraps syscall.Getdents and converts the result to []fuse.DirEntry.
// The function takes a path instead of an fd because we need to be able to
// call Lstat on files. Fstatat is not yet available in Go as of v1.9:
// https://github.com/golang/go/issues/14216
func Getdents(dir string) ([]fuse.DirEntry, error) {
	fd, err := syscall.Open(dir, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	// Collect syscall result in smartBuf.
	// "bytes.Buffer" is smart about expanding the capacity and avoids the
	// exponential runtime of simple append().
	var smartBuf bytes.Buffer
	tmp := make([]byte, 10000)
	for {
		n, err := syscall.Getdents(fd, tmp)
		if err != nil {
			return nil, err
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
		s := *(*syscall.Dirent)(unsafe.Pointer(&buf[offset]))
		if s.Reclen == 0 {
			tlog.Warn.Printf("Getdents: corrupt entry #%d: Reclen=0 at offset=%d. Returning EBADR",
				numEntries, offset)
			// EBADR = Invalid request descriptor
			return nil, syscall.EBADR
		}
		if int(s.Reclen) > sizeofDirent {
			tlog.Warn.Printf("Getdents: corrupt entry #%d: Reclen=%d > %d. Returning EBADR",
				numEntries, sizeofDirent, s.Reclen)
			return nil, syscall.EBADR
		}
		offset += int(s.Reclen)
		numEntries++
	}
	// Parse the buffer into entries
	entries := make([]fuse.DirEntry, 0, numEntries)
	offset = 0
	for offset < len(buf) {
		s := *(*syscall.Dirent)(unsafe.Pointer(&buf[offset]))
		name, err := getdentsName(s)
		if err != nil {
			return nil, err
		}
		offset += int(s.Reclen)
		if name == "." || name == ".." {
			// os.File.Readdir() drops "." and "..". Let's be compatible.
			continue
		}
		mode, err := convertDType(s.Type, dir+"/"+name)
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
	return entries, nil
}

// getdentsName extracts the filename from a Dirent struct and returns it as
// a Go string.
func getdentsName(s syscall.Dirent) (string, error) {
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

// convertDType converts a Dirent.Type to at Stat_t.Mode value.
func convertDType(dtype uint8, file string) (uint32, error) {
	if dtype != syscall.DT_UNKNOWN {
		// Shift up by four octal digits = 12 bits
		return uint32(dtype) << 12, nil
	}
	// DT_UNKNOWN: we have to call Lstat()
	var st syscall.Stat_t
	err := syscall.Lstat(file, &st)
	if err != nil {
		return 0, err
	}
	// The S_IFMT bit mask extracts the file type from the mode.
	return st.Mode & syscall.S_IFMT, nil
}
