package fusefrontend_reverse

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/inomap"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"

	"github.com/sabhiram/go-gitignore"
)

// RootNode is the root directory in a `gocryptfs -reverse` mount
type RootNode struct {
	Node
	// Stores configuration arguments
	args fusefrontend.Args
	// Filename encryption helper
	nameTransform *nametransform.NameTransform
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// Tests whether a path is excluded (hidden) from the user. Used by -exclude.
	excluder ignore.IgnoreParser
	// inoMap translates inode numbers from different devices to unique inode
	// numbers.
	inoMap *inomap.InoMap
	// rootDev stores the device number of the backing directory. Used for
	// --one-file-system.
	rootDev uint64
}

// NewRootNode returns an encrypted FUSE overlay filesystem.
// In this case (reverse mode) the backing directory is plain-text and
// ReverseFS provides an encrypted view.
func NewRootNode(args fusefrontend.Args, c *contentenc.ContentEnc, n *nametransform.NameTransform) *RootNode {
	var rootDev uint64
	var st syscall.Stat_t
	if err := syscall.Stat(args.Cipherdir, &st); err != nil {
		tlog.Warn.Printf("Could not stat backing directory %q: %v", args.Cipherdir, err)
		if args.OneFileSystem {
			tlog.Fatal.Printf("This is a fatal error in combination with -one-file-system")
			os.Exit(exitcodes.CipherDir)
		}
	} else {
		rootDev = uint64(st.Dev)
	}

	rn := &RootNode{
		args:          args,
		nameTransform: n,
		contentEnc:    c,
		inoMap:        inomap.New(rootDev),
		rootDev:       rootDev,
	}
	if len(args.Exclude) > 0 || len(args.ExcludeWildcard) > 0 || len(args.ExcludeFrom) > 0 {
		rn.excluder = prepareExcluder(args)
	}
	return rn
}

// You can pass either gocryptfs.longname.XYZ.name or gocryptfs.longname.XYZ.
func (rn *RootNode) findLongnameParent(fd int, diriv []byte, longname string) (pName string, cFullName string, errno syscall.Errno) {
	defer func() {
		tlog.Debug.Printf("findLongnameParent: %d %x %q -> %q %q %d\n", fd, diriv, longname, pName, cFullName, errno)
	}()
	if strings.HasSuffix(longname, nametransform.LongNameSuffix) {
		longname = nametransform.RemoveLongNameSuffix(longname)
	}
	entries, err := syscallcompat.Getdents(fd)
	if err != nil {
		errno = fs.ToErrno(err)
		return
	}
	for _, entry := range entries {
		if len(entry.Name) <= shortNameMax {
			continue
		}
		cFullName, err = rn.nameTransform.EncryptName(entry.Name, diriv)
		if err != nil {
			continue
		}
		if len(cFullName) <= unix.NAME_MAX {
			// Entry should have been skipped by the shortNameMax check above
			log.Panic("logic error or wrong shortNameMax constant?")
		}
		hName := rn.nameTransform.HashLongName(cFullName)
		if longname == hName {
			pName = entry.Name
			break
		}
	}
	if pName == "" {
		errno = syscall.ENOENT
		return
	}
	return
}

// isExcludedPlain finds out if the plaintext path "pPath" is
// excluded (used when -exclude is passed by the user).
func (rn *RootNode) isExcludedPlain(pPath string) bool {
	// root dir can't be excluded
	if pPath == "" {
		return false
	}
	return rn.excluder != nil && rn.excluder.MatchesPath(pPath)
}

// excludeDirEntries filters out directory entries that are "-exclude"d.
// pDir is the relative plaintext path to the directory these entries are
// from. The entries should be plaintext files.
func (rn *RootNode) excludeDirEntries(d *dirfdPlus, entries []fuse.DirEntry) (filtered []fuse.DirEntry) {
	if rn.excluder == nil {
		return entries
	}
	filtered = make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		// filepath.Join handles the case of pDir="" correctly:
		// Join("", "foo") -> "foo". This does not: pDir + "/" + name"
		p := filepath.Join(d.pPath, entry.Name)
		if rn.isExcludedPlain(p) {
			// Skip file
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}
