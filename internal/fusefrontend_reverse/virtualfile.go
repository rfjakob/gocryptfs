package fusefrontend_reverse

import (
	"syscall"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// virtualFileMode is the mode to use for virtual files (gocryptfs.diriv and
	// *.name). They are always readable, as stated in func Access
	virtualFileMode = syscall.S_IFREG | 0444
	// virtualInoBase is the start of the inode number range that is used
	// for virtual files.
	// The value 10^19 is just below 2^60. A power of 10 has been chosen so the
	// "ls -li" output (which is base-10) is easy to read.
	// 10^19 is the largest power of 10 that is smaller than UINT64_MAX/2.
	virtualInoBase = uint64(1000000000000000000)
)

func (rfs *ReverseFS) newDirIVFile(cRelPath string) (nodefs.File, fuse.Status) {
	cDir := saneDir(cRelPath)
	absDir, err := rfs.abs(rfs.decryptPath(cDir))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	return rfs.newVirtualFile(pathiv.Derive(cDir, pathiv.PurposeDirIV), absDir)
}

type virtualFile struct {
	// Embed nodefs.defaultFile for a ENOSYS implementation of all methods
	nodefs.File
	// file content
	content []byte
	// absolute path to a parent file
	parentFile string
}

// newVirtualFile creates a new in-memory file that does not have a representation
// on disk. "content" is the file content. Timestamps and file owner are copied
// from "parentFile" (absolute plaintext path). For a "gocryptfs.diriv" file, you
// would use the parent directory as "parentFile".
func (rfs *ReverseFS) newVirtualFile(content []byte, parentFile string) (nodefs.File, fuse.Status) {
	return &virtualFile{
		File:       nodefs.NewDefaultFile(),
		content:    content,
		parentFile: parentFile,
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
	var st syscall.Stat_t
	err := syscall.Lstat(f.parentFile, &st)
	if err != nil {
		tlog.Debug.Printf("GetAttr: Lstat %q: %v\n", f.parentFile, err)
		return fuse.ToStatus(err)
	}
	if st.Ino > virtualInoBase {
		tlog.Warn.Printf("virtualFile.GetAttr: parent file inode number %d crosses reserved space, max=%d. Returning EOVERFLOW.",
			st.Ino, virtualInoBase)
		return fuse.ToStatus(syscall.EOVERFLOW)
	}
	st.Ino = st.Ino + virtualInoBase
	st.Size = int64(len(f.content))
	st.Mode = virtualFileMode
	st.Nlink = 1
	a.FromStat(&st)
	return fuse.OK
}
