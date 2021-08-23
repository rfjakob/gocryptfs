package fusefrontend_reverse

import (
	"context"
	"log"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/pathiv"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

const (
	// File names are padded to 16-byte multiples, encrypted and
	// base64-encoded. We can encode at most 176 bytes to stay below the 255
	// bytes limit:
	// * base64(176 bytes) = 235 bytes
	// * base64(192 bytes) = 256 bytes (over 255!)
	// But the PKCS#7 padding is at least one byte. This means we can only use
	// 175 bytes for the file name.
	shortNameMax = 175
)

// translateSize translates the ciphertext size in `out` into plaintext size.
func (n *Node) translateSize(dirfd int, cName string, pName string, out *fuse.Attr) {
	if out.IsRegular() {
		rn := n.rootNode()
		out.Size = rn.contentEnc.PlainSizeToCipherSize(out.Size)
	} else if out.IsSymlink() {
		cLink, _ := n.readlink(dirfd, cName, pName)
		out.Size = uint64(len(cLink))
	}
}

// Path returns the relative plaintext path of this node
func (n *Node) Path() string {
	return n.Inode.Path(n.Root())
}

// rootNode returns the Root Node of the filesystem.
func (n *Node) rootNode() *RootNode {
	return n.Root().Operations().(*RootNode)
}

// dirfdPlus gets filled out as we gather information about a node
type dirfdPlus struct {
	// fd to the directory, opened with O_DIRECTORY|O_PATH
	dirfd int
	// Relative plaintext path
	pPath string
	// Plaintext basename: filepath.Base(pPath)
	pName string
	// Relative ciphertext path
	cPath string
	// Ciphertext basename: filepath.Base(cPath)
	cName string
}

// prepareAtSyscall returns a (dirfd, cName) pair that can be used
// with the "___at" family of system calls (openat, fstatat, unlinkat...) to
// access the backing encrypted directory.
//
// If you pass a `child` file name, the (dirfd, cName) pair will refer to
// a child of this node.
// If `child` is empty, the (dirfd, cName) pair refers to this node itself.
func (n *Node) prepareAtSyscall(child string) (d *dirfdPlus, errno syscall.Errno) {
	cPath := n.Path()
	if child != "" {
		cPath = filepath.Join(cPath, child)
	}
	rn := n.rootNode()
	dirfd, pPath, err := rn.openBackingDir(cPath)
	if err != nil {
		errno = fs.ToErrno(err)
	}
	d = &dirfdPlus{
		dirfd: dirfd,
		pPath: pPath,
		pName: filepath.Base(pPath),
		cPath: cPath,
		cName: filepath.Base(cPath),
	}
	return
}

// newChild attaches a new child inode to n.
// The passed-in `st` will be modified to get a unique inode number.
func (n *Node) newChild(ctx context.Context, st *syscall.Stat_t, out *fuse.EntryOut) *fs.Inode {
	isOtherFilesystem := (uint64(st.Dev) != n.rootNode().rootDev)
	// Get unique inode number
	rn := n.rootNode()
	rn.inoMap.TranslateStat(st)
	out.Attr.FromStat(st)
	// Create child node
	id := fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		Ino:  st.Ino,
	}
	node := &Node{
		isOtherFilesystem: isOtherFilesystem,
	}
	return n.NewInode(ctx, node, id)
}

// isRoot returns true if this node is the root node
func (n *Node) isRoot() bool {
	rn := n.rootNode()
	return &rn.Node == n
}

func (n *Node) lookupLongnameName(ctx context.Context, nameFile string, out *fuse.EntryOut) (ch *fs.Inode, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	// Find the file the gocryptfs.longname.XYZ.name file belongs to in the
	// directory listing
	fd, err := syscallcompat.Openat(d.dirfd, d.pName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	defer syscall.Close(fd)
	rn := n.rootNode()
	diriv := rn.deriveDirIV(d.cPath)
	pName, cFullname, errno := rn.findLongnameParent(fd, diriv, nameFile)
	if errno != 0 {
		return
	}
	if rn.isExcludedPlain(filepath.Join(d.cPath, pName)) {
		errno = syscall.EPERM
		return
	}
	// Get attrs from parent file
	st, err := syscallcompat.Fstatat2(fd, pName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	var vf *VirtualMemNode
	vf, errno = n.newVirtualMemNode([]byte(cFullname), st, inoTagNameFile)
	if errno != 0 {
		return nil, errno
	}
	out.Attr = vf.attr
	// Create child node
	id := fs.StableAttr{Mode: uint32(vf.attr.Mode), Gen: 1, Ino: vf.attr.Ino}
	ch = n.NewInode(ctx, vf, id)
	return

}

// lookupDiriv returns a new Inode for a gocryptfs.diriv file inside `n`.
func (n *Node) lookupDiriv(ctx context.Context, out *fuse.EntryOut) (ch *fs.Inode, errno syscall.Errno) {
	if rn := n.rootNode(); rn.args.DeterministicNames {
		log.Panic("BUG: lookupDiriv called but DeterministicNames is set")
	}

	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)
	st, err := syscallcompat.Fstatat2(d.dirfd, d.pName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	content := pathiv.Derive(d.cPath, pathiv.PurposeDirIV)
	var vf *VirtualMemNode
	vf, errno = n.newVirtualMemNode(content, st, inoTagDirIV)
	if errno != 0 {
		return nil, errno
	}
	out.Attr = vf.attr
	// Create child node
	id := fs.StableAttr{Mode: uint32(vf.attr.Mode), Gen: 1, Ino: vf.attr.Ino}
	ch = n.NewInode(ctx, vf, id)
	return
}

// lookupConf returns a new Inode for the gocryptfs.conf file
func (n *Node) lookupConf(ctx context.Context, out *fuse.EntryOut) (ch *fs.Inode, errno syscall.Errno) {
	rn := n.rootNode()
	p := filepath.Join(rn.args.Cipherdir, configfile.ConfReverseName)
	var st syscall.Stat_t
	err := syscall.Stat(p, &st)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	// Get unique inode number
	rn.inoMap.TranslateStat(&st)
	out.Attr.FromStat(&st)
	// Create child node
	id := fs.StableAttr{
		Mode: uint32(st.Mode),
		Gen:  1,
		Ino:  st.Ino,
	}
	node := &VirtualConfNode{path: p}
	ch = n.NewInode(ctx, node, id)
	return
}

// readlink reads and encrypts a symlink. Used by Readlink, Getattr, Lookup.
func (n *Node) readlink(dirfd int, cName string, pName string) (out []byte, errno syscall.Errno) {
	plainTarget, err := syscallcompat.Readlinkat(dirfd, pName)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	rn := n.rootNode()
	if rn.args.PlaintextNames {
		return []byte(plainTarget), 0
	}
	// Nonce is derived from the relative *ciphertext* path
	p := filepath.Join(n.Path(), cName)
	nonce := pathiv.Derive(p, pathiv.PurposeSymlinkIV)
	// Symlinks are encrypted like file contents and base64-encoded
	cBinTarget := rn.contentEnc.EncryptBlockNonce([]byte(plainTarget), 0, nil, nonce)
	cTarget := rn.nameTransform.B64EncodeToString(cBinTarget)
	// The kernel will reject a symlink target above 4096 chars and return
	// and I/O error to the user. Better emit the proper error ourselves.
	if len(cTarget) > syscallcompat.PATH_MAX {
		errno = syscall.ENAMETOOLONG
		return
	}
	return []byte(cTarget), 0
}
