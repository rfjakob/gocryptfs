package fusefrontend

import (
	"runtime"
	"syscall"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// prepareAtSyscallDirect is the direct version without Unicode normalization fallback
func (n *Node) prepareAtSyscallDirect(child string) (dirfd int, cName string, errno syscall.Errno) {
	if child == "" {
		tlog.Warn.Printf("BUG: prepareAtSyscallDirect: child=%q, should have called prepareAtSyscallMyself", child)
		return n.prepareAtSyscallMyself()
	}

	rn := n.rootNode()

	// All filesystem operations go through here, so this is a good place
	// to reset the idle marker.
	rn.IsIdle.Store(false)

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

// migrateFilename migrates a filename from NFD to NFC form
func (n *Node) migrateFilename(oldName, newName string) syscall.Errno {
	if oldName == newName {
		return 0 // Nothing to do
	}

	rn := n.rootNode()
	
	// Get directory file descriptor
	dirfd, _, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return errno
	}
	defer syscall.Close(dirfd)

	// For plaintext names: simple rename
	if rn.args.PlaintextNames {
		err := syscallcompat.Renameat(dirfd, oldName, dirfd, newName)
		return fs.ToErrno(err)
	}

	// For encrypted names: encrypt both names and rename
	iv, err := rn.nameTransform.ReadDirIVAt(dirfd)
	if err != nil {
		return fs.ToErrno(err)
	}

	var encryptName func(int, string, []byte) (string, error)
	if rn.nameTransform.HaveBadnamePatterns() {
		encryptName = func(dirfd int, child string, iv []byte) (string, error) {
			return rn.nameTransform.EncryptAndHashBadName(child, iv, dirfd)
		}
	} else {
		encryptName = func(dirfd int, child string, iv []byte) (string, error) {
			return rn.nameTransform.EncryptAndHashName(child, iv)
		}
	}

	oldCName, err := encryptName(dirfd, oldName, iv)
	if err != nil {
		return fs.ToErrno(err)
	}

	newCName, err := encryptName(dirfd, newName, iv)
	if err != nil {
		return fs.ToErrno(err)
	}

	err = syscallcompat.Renameat(dirfd, oldCName, dirfd, newCName)
	return fs.ToErrno(err)
}

// prepareAtSyscall returns a (dirfd, cName) pair that can be used
// with the "___at" family of system calls (openat, fstatat, unlinkat...) to
// access the backing encrypted child file.
func (n *Node) prepareAtSyscall(child string) (dirfd int, cName string, errno syscall.Errno) {
	if child == "" {
		tlog.Warn.Printf("BUG: prepareAtSyscall: child=%q, should have called prepareAtSyscallMyself", child)
		return n.prepareAtSyscallMyself()
	}

	// On macOS, implement Unicode normalization with fallback and migration
	if runtime.GOOS == "darwin" && utf8.ValidString(child) {
		// Step 1: Always try NFC first (canonical storage form)
		normalizedChild := norm.NFC.String(child)
		dirfd, cName, errno = n.prepareAtSyscallDirect(normalizedChild)
		if errno == 0 {
			return dirfd, cName, 0 // Found NFC version
		}
		
		// Only proceed with fallback if we got ENOENT (file not found)
		if errno != syscall.ENOENT {
			return dirfd, cName, errno
		}

		// Step 2: Try alternate form if input was different
		if normalizedChild != child {
			// Input was NFD, try original NFD form
			dirfdNFD, cNameNFD, errnoNFD := n.prepareAtSyscallDirect(child)
			if errnoNFD == 0 {
				// Found NFD file - migrate it to NFC
				if errno := n.migrateFilename(child, normalizedChild); errno == 0 {
					// Migration successful, use NFC
					syscall.Close(dirfdNFD) // Close the NFD dirfd
					return n.prepareAtSyscallDirect(normalizedChild)
				} else {
					// Migration failed, use NFD
					return dirfdNFD, cNameNFD, 0
				}
			}
		}

		// Step 3: If input was NFC, also try NFD as fallback
		if normalizedChild == child {
			nfdChild := norm.NFD.String(child)
			if nfdChild != child {
				dirfdNFD, cNameNFD, errnoNFD := n.prepareAtSyscallDirect(nfdChild)
				if errnoNFD == 0 {
					// Found NFD file - migrate it to NFC
					if errno := n.migrateFilename(nfdChild, normalizedChild); errno == 0 {
						// Migration successful, use NFC
						syscall.Close(dirfdNFD) // Close the NFD dirfd
						return n.prepareAtSyscallDirect(normalizedChild)
					} else {
						// Migration failed, use NFD
						return dirfdNFD, cNameNFD, 0
					}
				}
			}
		}
	}

	return n.prepareAtSyscallDirect(child) // Non-macOS or fallback
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
