package fusefrontend_reverse

import (
	"fmt"
	"syscall"
	"os"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
)

func (rfs *ReverseFS) newDirIVFile(cRelPath string) (nodefs.File, fuse.Status) {
	cDir := saneDir(cRelPath)
	absDir, err := rfs.abs(rfs.decryptPath(cDir))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}

	fi, err := os.Stat(absDir)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	st := fi.Sys().(*syscall.Stat_t)

	return rfs.newVirtualFile(derivePathIV(cDir, ivPurposeDirIV), absDir, st.Uid, st.Gid)
}

type virtualFile struct {
	// Embed nodefs.defaultFile for a ENOSYS implementation of all methods
	nodefs.File
	// file content
	content []byte
	// absolute path to a parent file
	parentFile string
	// inode number
	ino uint64
	// Owner UID
	Uid uint32
	// Owner GID
	Gid uint32
}

func (rfs *ReverseFS) newVirtualFile(content []byte, parentFile string, ownerUid uint32, ownerGid uint32) (nodefs.File, fuse.Status) {
	return &virtualFile{
		File:       nodefs.NewDefaultFile(),
		content:    content,
		parentFile: parentFile,
		ino:        rfs.inoGen.next(),
		Uid:	    ownerUid,
		Gid:	    ownerGid,
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
		fmt.Printf("Lstat %q: %v\n", f.parentFile, err)
		return fuse.ToStatus(err)
	}
	st.Ino = f.ino
	st.Size = int64(len(f.content))
	st.Mode = virtualFileMode
	st.Nlink = 1
	a.FromStat(&st)
	a.Owner.Uid = f.Uid
	a.Owner.Gid = f.Gid
	return fuse.OK
}
