package fusefrontend_reverse

import (
	"log"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/inomap"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// virtualFileMode is the mode to use for virtual files (gocryptfs.diriv and
	// *.name). They are always readable, as stated in func Access
	virtualFileMode = syscall.S_IFREG | 0444
	// We use inomap's `Tag` feature to generate unique inode numbers for
	// virtual files. These are the tags we use.
	inoTagDirIV    = 1
	inoTagNameFile = 2
)

func (rfs *ReverseFS) newDirIVFile(cRelPath string) (nodefs.File, fuse.Status) {
	cDir := nametransform.Dir(cRelPath)
	dir, err := rfs.decryptPath(cDir)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	iv := pathiv.Derive(cDir, pathiv.PurposeDirIV)
	return rfs.newVirtualFile(iv, rfs.args.Cipherdir, dir, inoTagDirIV)
}

type virtualFile struct {
	// Embed nodefs.defaultFile for a ENOSYS implementation of all methods
	nodefs.File
	// pointer to parent filesystem
	rfs *ReverseFS
	// file content
	content []byte
	// backing directory
	cipherdir string
	// path to a parent file (relative to cipherdir)
	parentFile string
	// inomap `Tag`.
	// Depending on the file type, either `inoTagDirIV` or `inoTagNameFile`.
	inoTag uint8
}

// newVirtualFile creates a new in-memory file that does not have a representation
// on disk. "content" is the file content. Timestamps and file owner are copied
// from "parentFile" (plaintext path relative to "cipherdir").
// For a "gocryptfs.diriv" file, you would use the parent directory as
// "parentFile".
func (rfs *ReverseFS) newVirtualFile(content []byte, cipherdir string, parentFile string, inoTag uint8) (nodefs.File, fuse.Status) {
	if inoTag == 0 {
		log.Panicf("BUG: inoTag for virtual file is zero - this will cause ino collisions!")
	}
	return &virtualFile{
		File:       nodefs.NewDefaultFile(),
		rfs:        rfs,
		content:    content,
		cipherdir:  cipherdir,
		parentFile: parentFile,
		inoTag:     inoTag,
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
	var st2 unix.Stat_t
	err = syscallcompat.Fstatat(dirfd, name, &st2, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		tlog.Debug.Printf("GetAttr: Fstatat %q: %v\n", f.parentFile, err)
		return fuse.ToStatus(err)
	}
	st := syscallcompat.Unix2syscall(st2)
	q := inomap.NewQIno(uint64(st.Dev), f.inoTag, uint64(st.Ino))
	st.Ino = f.rfs.inoMap.Translate(q)
	st.Size = int64(len(f.content))
	st.Mode = virtualFileMode
	st.Nlink = 1
	a.FromStat(&st)
	return fuse.OK
}
