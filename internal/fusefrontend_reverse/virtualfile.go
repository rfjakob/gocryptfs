package fusefrontend_reverse

import (
	"log"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// virtualFileMode is the mode to use for virtual files (gocryptfs.diriv and
	// *.name). They are always readable, as stated in func Access
	virtualFileMode = syscall.S_IFREG | 0444
	// inoBaseDirIV is the start of the inode number range that is used
	// for virtual gocryptfs.diriv files. inoBaseNameFile is the thing for
	// *.name files.
	// The value 10^19 is just below 2^60. A power of 10 has been chosen so the
	// "ls -li" output (which is base-10) is easy to read.
	// 10^19 is the largest power of 10 that is smaller than
	// INT64_MAX (=UINT64_MAX/2). This avoids signedness issues.
	inoBaseDirIV    = uint64(1000000000000000000)
	inoBaseNameFile = uint64(2000000000000000000)
	// inoBaseMin marks the start of the inode number space that is
	// reserved for virtual files. It is the lowest of the inoBaseXXX values
	// above.
	inoBaseMin = inoBaseDirIV
)

func (rfs *ReverseFS) newDirIVFile(cRelPath string) (nodefs.File, fuse.Status) {
	cDir := nametransform.Dir(cRelPath)
	dir, err := rfs.decryptPath(cDir)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	iv := pathiv.Derive(cDir, pathiv.PurposeDirIV)
	return rfs.newVirtualFile(iv, rfs.args.Cipherdir, dir, inoBaseDirIV)
}

type virtualFile struct {
	// Embed nodefs.defaultFile for a ENOSYS implementation of all methods
	nodefs.File
	// file content
	content []byte
	// backing directory
	cipherdir string
	// path to a parent file (relative to cipherdir)
	parentFile string
	// inode number of a virtual file is inode of parent file plus inoBase
	inoBase uint64
}

// newVirtualFile creates a new in-memory file that does not have a representation
// on disk. "content" is the file content. Timestamps and file owner are copied
// from "parentFile" (plaintext path relative to "cipherdir").
// For a "gocryptfs.diriv" file, you would use the parent directory as
// "parentFile".
func (rfs *ReverseFS) newVirtualFile(content []byte, cipherdir string, parentFile string, inoBase uint64) (nodefs.File, fuse.Status) {
	if inoBase < inoBaseMin {
		log.Panicf("BUG: virtual inode number base %d is below reserved space", inoBase)
	}
	return &virtualFile{
		File:       nodefs.NewDefaultFile(),
		content:    content,
		cipherdir:  cipherdir,
		parentFile: parentFile,
		inoBase:    inoBase,
	}, fuse.OK
}

// Read - FUSE call
func (f *virtualFile) Read(buf []byte, off int64) (resultData fuse.ReadResult, status fuse.Status) {
	if off >= int64(len(f.content)) {
		return nil, fuse.OK
	}
	end := int(off) + len(buf)
	if end > len(f.content) {
		end = len(f.content)
	}
	return fuse.ReadResultData(f.content[off:end]), fuse.OK
}

// GetAttr - FUSE call
func (f *virtualFile) GetAttr(a *fuse.Attr) fuse.Status {
	dir := filepath.Dir(f.parentFile)
	dirfd, err := syscallcompat.OpenDirNofollow(f.cipherdir, dir)
	if err != nil {
		return fuse.ToStatus(err)
	}
	defer syscall.Close(dirfd)
	name := filepath.Base(f.parentFile)
	var st unix.Stat_t
	err = syscallcompat.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		tlog.Debug.Printf("GetAttr: Fstatat %q: %v\n", f.parentFile, err)
		return fuse.ToStatus(err)
	}
	if st.Ino > inoBaseMin {
		tlog.Warn.Printf("virtualFile.GetAttr: parent file inode number %d crosses reserved space, max=%d. Returning EOVERFLOW.",
			st.Ino, inoBaseMin)
		return fuse.ToStatus(syscall.EOVERFLOW)
	}
	st.Ino = st.Ino + f.inoBase
	st.Size = int64(len(f.content))
	st.Mode = virtualFileMode
	st.Nlink = 1
	st2 := syscallcompat.Unix2syscall(st)
	a.FromStat(&st2)
	return fuse.OK
}
