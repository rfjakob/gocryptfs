package fusefrontend

import (
	"sync/atomic"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// prepareAtSyscall returns a (dirfd, cName) pair that can be used
// with the "___at" family of system calls (openat, fstatat, unlinkat...) to
// access the backing encrypted child file.
func (n *Node) prepareAtSyscall(child string) (dirfd int, cName string, errno syscall.Errno) {
	if child == "" {
		tlog.Warn.Printf("BUG: prepareAtSyscall: child=%q, should have called prepareAtSyscallMyself", child)
		return n.prepareAtSyscallMyself()
	}

	rn := n.rootNode()

	// All filesystem operations go through here, so this is a good place
	// to reset the idle marker.
	atomic.StoreUint32(&rn.IsIdle, 0)

	if n.IsRoot() && rn.isFiltered(child) {
		return -1, "", syscall.EPERM
	}

	var encryptName func(int, string, []byte) (string, error)
	if !rn.args.PlaintextNames {
		encryptName = func(dirfd int, child string, iv []byte) (cName string, err error) {
			// Badname allowed, try to determine filenames
			if rn.nameTransform.HaveBadnamePatterns() {
				return rn.nameTransform.EncryptAndHashBadName(child, iv, dirfd)
			}
			return rn.nameTransform.EncryptAndHashName(child, iv)
		}
	}

	// Cache lookup
	var iv []byte
	dirfd, iv = rn.dirCache.Lookup(n)
	if dirfd > 0 {
		if rn.args.PlaintextNames {
			return dirfd, child, 0
		}
		var err error
		cName, err = encryptName(dirfd, child, iv)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", fs.ToErrno(err)
		}
		return
	}

	// Slowpath: Open ourselves & read diriv
	parentDirfd, myCName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(parentDirfd)

	dirfd, err := syscallcompat.Openat(parentDirfd, myCName, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		return -1, "", fs.ToErrno(err)
	}

	// Cache store
	if !rn.args.PlaintextNames {
		var err error
		iv, err = rn.nameTransform.ReadDirIVAt(dirfd)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", fs.ToErrno(err)
		}
	}
	rn.dirCache.Store(n, dirfd, iv)

	if rn.args.PlaintextNames {
		return dirfd, child, 0
	}

	cName, err = encryptName(dirfd, child, iv)
	if err != nil {
		syscall.Close(dirfd)
		return -1, "", fs.ToErrno(err)
	}

	return
}

func (n *Node) prepareAtSyscallMyself() (dirfd int, cName string, errno syscall.Errno) {
	dirfd = -1

	// Handle root node
	if n.IsRoot() {
		var err error
		rn := n.rootNode()
		// Open cipherdir (following symlinks)
		dirfd, err = syscallcompat.Open(rn.args.Cipherdir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err != nil {
			return -1, "", fs.ToErrno(err)
		}
		return dirfd, ".", 0
	}

	// Otherwise convert to prepareAtSyscall of parent node
	myName, p1 := n.Parent()
	if p1 == nil || myName == "" {
		errno = syscall.ENOENT
		return
	}
	parent := toNode(p1.Operations())
	return parent.prepareAtSyscall(myName)
}
