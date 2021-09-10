package fusefrontend

import (
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/inomap"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// RootNode is the root of the filesystem tree of Nodes.
type RootNode struct {
	Node
	// args stores configuration arguments
	args Args
	// dirIVLock: Lock()ed if any "gocryptfs.diriv" file is modified
	// Readers must RLock() it to prevent them from seeing intermediate
	// states
	dirIVLock sync.RWMutex
	// Filename encryption helper
	nameTransform *nametransform.NameTransform
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// This lock is used by openWriteOnlyFile() to block concurrent opens while
	// it relaxes the permissions on a file.
	openWriteOnlyLock sync.RWMutex
	// MitigatedCorruptions is used to report data corruption that is internally
	// mitigated by ignoring the corrupt item. For example, when OpenDir() finds
	// a corrupt filename, we still return the other valid filenames.
	// The corruption is logged to syslog to inform the user,	and in addition,
	// the corrupt filename is logged to this channel via
	// reportMitigatedCorruption().
	// "gocryptfs -fsck" reads from the channel to also catch these transparently-
	// mitigated corruptions.
	MitigatedCorruptions chan string
	// IsIdle flag is set to zero each time fs.isFiltered() is called
	// (uint32 so that it can be reset with CompareAndSwapUint32).
	// When -idle was used when mounting, idleMonitor() sets it to 1
	// periodically.
	IsIdle uint32
	// dirCache caches directory fds
	dirCache dirCache
	// inoMap translates inode numbers from different devices to unique inode
	// numbers.
	inoMap *inomap.InoMap
	// gen is the node generation numbers. Normally, it is always set to 1,
	// but -sharestorage uses an incrementing counter for new nodes.
	// This makes each directory entry unique (even hard links),
	// makes go-fuse hand out separate FUSE Node IDs for each, and prevents
	// bizarre problems when inode numbers are reused behind our back.
	gen uint64
	// quirks is a bitmap that enables workaround for quirks in the filesystem
	// backing the cipherdir
	quirks uint64
}

func NewRootNode(args Args, c *contentenc.ContentEnc, n *nametransform.NameTransform) *RootNode {
	var rootDev uint64
	var st syscall.Stat_t
	if err := syscall.Stat(args.Cipherdir, &st); err != nil {
		tlog.Warn.Printf("Could not stat backing directory %q: %v", args.Cipherdir, err)
	} else {
		rootDev = uint64(st.Dev)
	}

	if len(args.Exclude) > 0 {
		tlog.Warn.Printf("Forward mode does not support -exclude")
	}

	ivLen := nametransform.DirIVLen
	if args.PlaintextNames {
		ivLen = 0
	}

	rn := &RootNode{
		args:          args,
		nameTransform: n,
		contentEnc:    c,
		inoMap:        inomap.New(rootDev),
		dirCache:      dirCache{ivLen: ivLen},
		quirks:        syscallcompat.DetectQuirks(args.Cipherdir),
	}
	return rn
}

// main.doMount() calls this after unmount
func (rn *RootNode) AfterUnmount() {
	// print stats before we exit
	rn.dirCache.stats()
}

// mangleOpenFlags is used by Create() and Open() to convert the open flags the user
// wants to the flags we internally use to open the backing file.
// The returned flags always contain O_NOFOLLOW.
func (rn *RootNode) mangleOpenFlags(flags uint32) (newFlags int) {
	newFlags = int(flags)
	// Convert WRONLY to RDWR. We always need read access to do read-modify-write cycles.
	if (newFlags & syscall.O_ACCMODE) == syscall.O_WRONLY {
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND
	// O_DIRECT accesses must be aligned in both offset and length. Due to our
	// crypto header, alignment will be off, even if userspace makes aligned
	// accesses. Running xfstests generic/013 on ext4 used to trigger lots of
	// EINVAL errors due to missing alignment. Just fall back to buffered IO.
	newFlags = newFlags &^ syscallcompat.O_DIRECT
	// Create and Open are two separate FUSE operations, so O_CREAT should not
	// be part of the open flags.
	newFlags = newFlags &^ syscall.O_CREAT
	// We always want O_NOFOLLOW to be safe against symlink races
	newFlags |= syscall.O_NOFOLLOW
	return newFlags
}

// reportMitigatedCorruption is used to report a corruption that was transparently
// mitigated and did not return an error to the user. Pass the name of the corrupt
// item (filename for OpenDir(), xattr name for ListXAttr() etc).
// See the MitigatedCorruptions channel for more info.
func (rn *RootNode) reportMitigatedCorruption(item string) {
	if rn.MitigatedCorruptions == nil {
		return
	}
	select {
	case rn.MitigatedCorruptions <- item:
	case <-time.After(1 * time.Second):
		tlog.Warn.Printf("BUG: reportCorruptItem: timeout")
		//debug.PrintStack()
		return
	}
}

// isFiltered - check if plaintext file "child" should be forbidden
//
// Prevents name clashes with internal files when file names are not encrypted
func (rn *RootNode) isFiltered(child string) bool {
	if !rn.args.PlaintextNames {
		return false
	}
	// gocryptfs.conf in the root directory is forbidden
	if child == configfile.ConfDefaultName {
		tlog.Info.Printf("The name /%s is reserved when -plaintextnames is used\n",
			configfile.ConfDefaultName)
		return true
	}
	// Note: gocryptfs.diriv is NOT forbidden because diriv and plaintextnames
	// are exclusive
	return false
}

// decryptSymlinkTarget: "cData64" is base64-decoded and decrypted
// like file contents (GCM).
// The empty string decrypts to the empty string.
//
// This function does not do any I/O and is hence symlink-safe.
func (rn *RootNode) decryptSymlinkTarget(cData64 string) (string, error) {
	if cData64 == "" {
		return "", nil
	}
	cData, err := rn.nameTransform.B64DecodeString(cData64)
	if err != nil {
		return "", err
	}
	data, err := rn.contentEnc.DecryptBlock([]byte(cData), 0, nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Due to RMW, we always need read permissions on the backing file. This is a
// problem if the file permissions do not allow reading (i.e. 0200 permissions).
// This function works around that problem by chmod'ing the file, obtaining a fd,
// and chmod'ing it back.
func (rn *RootNode) openWriteOnlyFile(dirfd int, cName string, newFlags int) (rwFd int, err error) {
	woFd, err := syscallcompat.Openat(dirfd, cName, syscall.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	defer syscall.Close(woFd)
	var st syscall.Stat_t
	err = syscall.Fstat(woFd, &st)
	if err != nil {
		return
	}
	// The cast to uint32 fixes a build failure on Darwin, where st.Mode is uint16.
	perms := uint32(st.Mode)
	// Verify that we don't have read permissions
	if perms&0400 != 0 {
		tlog.Warn.Printf("openWriteOnlyFile: unexpected permissions %#o, returning EPERM", perms)
		err = syscall.EPERM
		return
	}
	// Upgrade the lock to block other Open()s and downgrade again on return
	rn.openWriteOnlyLock.RUnlock()
	rn.openWriteOnlyLock.Lock()
	defer func() {
		rn.openWriteOnlyLock.Unlock()
		rn.openWriteOnlyLock.RLock()
	}()
	// Relax permissions and revert on return
	err = syscall.Fchmod(woFd, perms|0400)
	if err != nil {
		tlog.Warn.Printf("openWriteOnlyFile: changing permissions failed: %v", err)
		return
	}
	defer func() {
		err2 := syscall.Fchmod(woFd, perms)
		if err2 != nil {
			tlog.Warn.Printf("openWriteOnlyFile: reverting permissions failed: %v", err2)
		}
	}()
	return syscallcompat.Openat(dirfd, cName, newFlags, 0)
}

// encryptSymlinkTarget: "data" is encrypted like file contents (GCM)
// and base64-encoded.
// The empty string encrypts to the empty string.
//
// Symlink-safe because it does not do any I/O.
func (rn *RootNode) encryptSymlinkTarget(data string) (cData64 string) {
	if data == "" {
		return ""
	}
	cData := rn.contentEnc.EncryptBlock([]byte(data), 0, nil)
	cData64 = rn.nameTransform.B64EncodeToString(cData)
	return cData64
}

// encryptXattrValue encrypts the xattr value "data".
// The data is encrypted like a file content block, but without binding it to
// a file location (block number and file id are set to zero).
// Special case: an empty value is encrypted to an empty value.
func (rn *RootNode) encryptXattrValue(data []byte) (cData []byte) {
	if len(data) == 0 {
		return []byte{}
	}
	return rn.contentEnc.EncryptBlock(data, 0, nil)
}

// decryptXattrValue decrypts the xattr value "cData".
func (rn *RootNode) decryptXattrValue(cData []byte) (data []byte, err error) {
	if len(cData) == 0 {
		return []byte{}, nil
	}
	data, err1 := rn.contentEnc.DecryptBlock([]byte(cData), 0, nil)
	if err1 == nil {
		return data, nil
	}
	// This backward compatibility is needed to support old
	// file systems having xattr values base64-encoded.
	cData, err2 := rn.nameTransform.B64DecodeString(string(cData))
	if err2 != nil {
		// Looks like the value was not base64-encoded, but just corrupt.
		// Return the original decryption error: err1
		return nil, err1
	}
	return rn.contentEnc.DecryptBlock([]byte(cData), 0, nil)
}

// encryptXattrName transforms "user.foo" to "user.gocryptfs.a5sAd4XAa47f5as6dAf"
func (rn *RootNode) encryptXattrName(attr string) (string, error) {
	// xattr names are encrypted like file names, but with a fixed IV.
	cAttr, err := rn.nameTransform.EncryptName(attr, xattrNameIV)
	if err != nil {
		return "", err
	}
	return xattrStorePrefix + cAttr, nil
}

func (rn *RootNode) decryptXattrName(cAttr string) (attr string, err error) {
	// Reject anything that does not start with "user.gocryptfs."
	if !strings.HasPrefix(cAttr, xattrStorePrefix) {
		return "", syscall.EINVAL
	}
	// Strip "user.gocryptfs." prefix
	cAttr = cAttr[len(xattrStorePrefix):]
	attr, err = rn.nameTransform.DecryptName(cAttr, xattrNameIV)
	if err != nil {
		return "", err
	}
	return attr, nil
}
