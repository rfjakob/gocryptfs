package fusefrontend_reverse

import (
	"context"
	"log"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/inomap"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
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

type fileType int

// Values returned by lookupFileType
const (
	// A real file/directory/symlink in the backing plaintext directory
	typeReal fileType = iota
	// A DirIV (gocryptfs.diriv) file
	typeDiriv
	// A gocryptfs.longname.*.name file for a file with a long name
	typeName
	// The config file gocryptfs.conf
	typeConfig
)

// lookupFileType returns the type of child file name
// (one of the fileType constants above). Called from Lookup().
func (n *Node) lookupFileType(cName string) fileType {
	rn := n.rootNode()
	// In -plaintextname mode, neither diriv nor longname files exist.
	if !rn.args.PlaintextNames {
		if !rn.args.DeterministicNames {
			// Is it a gocryptfs.diriv file?
			if cName == nametransform.DirIVFilename {
				return typeDiriv
			}
		}
		// Is it a gocryptfs.longname.*.name file?
		if t := nametransform.NameType(cName); t == nametransform.LongNameFilename {
			return typeName
		}
	}
	// gocryptfs.conf in the root directory. This is passed through to
	// .gocryptfs.reverse.conf in the backing plaintext directory.
	if n.isRoot() && !rn.args.ConfigCustom && cName == configfile.ConfDefaultName {
		return typeConfig
	}
	return typeReal
}

// VirtualMemNode is an in-memory node that does not have a representation
// on disk.
type VirtualMemNode struct {
	fs.Inode

	// file content
	content []byte
	// attributes for Getattr()
	attr fuse.Attr
}

// newVirtualMemNode creates a new in-memory file that does not have a representation
// on disk. "content" is the file content. Timestamps and file owner are copied
// from "parentFile" (file descriptor).
// For a "gocryptfs.diriv" file, you would use the parent directory as
// "parentFile".
func (n *Node) newVirtualMemNode(content []byte, parentStat *syscall.Stat_t, inoTag uint8) (vf *VirtualMemNode, errno syscall.Errno) {
	if inoTag == 0 {
		log.Panicf("BUG: inoTag for virtual file is zero - this will cause ino collisions!")
	}

	// Adjust inode number and size
	rn := n.rootNode()
	st := parentStat
	q := inomap.NewQIno(uint64(st.Dev), inoTag, uint64(st.Ino))
	st.Ino = rn.inoMap.Translate(q)
	st.Size = int64(len(content))
	st.Mode = virtualFileMode
	st.Nlink = 1
	var a fuse.Attr
	a.FromStat(st)

	vf = &VirtualMemNode{content: content, attr: a}
	return
}

// Open - FUSE call
func (f *VirtualMemNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	return nil, fuse.FOPEN_KEEP_CACHE, 0
}

// GetAttr - FUSE call
func (f *VirtualMemNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Attr = f.attr
	return 0
}

// Read - FUSE call
func (f *VirtualMemNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	end := int(off) + len(dest)
	if end > len(f.content) {
		end = len(f.content)
	}
	return fuse.ReadResultData(f.content[off:end]), 0
}
