package fusefrontend_reverse

import (
	"context"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Readdir - FUSE call.
//
// This function is symlink-safe through use of openBackingDir() and
// ReadDirIVAt().
func (n *Node) Readdir(ctx context.Context) (stream fs.DirStream, errno syscall.Errno) {
	d, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(d.dirfd)

	// Read plaintext directory
	var entries []fuse.DirEntry
	fd, err := syscallcompat.Openat(d.dirfd, d.pName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(fd)
	entries, err = syscallcompat.Getdents(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}

	rn := n.rootNode()

	// Filter out excluded entries
	entries = rn.excludeDirEntries(d, entries)

	if rn.args.PlaintextNames {
		return n.readdirPlaintextnames(entries)
	}

	// Virtual files: at least one gocryptfs.diriv file
	virtualFiles := []fuse.DirEntry{
		{Mode: virtualFileMode, Name: nametransform.DirIVFilename},
	}

	dirIV := pathiv.Derive(d.cPath, pathiv.PurposeDirIV)
	// Encrypt names
	for i := range entries {
		var cName string
		// ".gocryptfs.reverse.conf" in the root directory is mapped to "gocryptfs.conf"
		if n.isRoot() && entries[i].Name == configfile.ConfReverseName &&
			!rn.args.ConfigCustom {
			cName = configfile.ConfDefaultName
		} else {
			cName = rn.nameTransform.EncryptName(entries[i].Name, dirIV)
			if len(cName) > unix.NAME_MAX {
				cName = rn.nameTransform.HashLongName(cName)
				dotNameFile := fuse.DirEntry{
					Mode: virtualFileMode,
					Name: cName + nametransform.LongNameSuffix,
				}
				virtualFiles = append(virtualFiles, dotNameFile)
			}
		}
		entries[i].Name = cName
	}

	// Add virtual files
	entries = append(entries, virtualFiles...)
	return fs.NewListDirStream(entries), 0
}

func (n *Node) readdirPlaintextnames(entries []fuse.DirEntry) (stream fs.DirStream, errno syscall.Errno) {
	rn := n.rootNode()
	// If we are not the root dir or a custom config path was used, we don't
	// need to map anything
	if !n.isRoot() || rn.args.ConfigCustom {
		return fs.NewListDirStream(entries), 0
	}
	// We are in the root dir and the default config file name
	// ".gocryptfs.reverse.conf" is used. We map it to "gocryptfs.conf".
	dupe := -1
	for i := range entries {
		if entries[i].Name == configfile.ConfReverseName {
			entries[i].Name = configfile.ConfDefaultName
		} else if entries[i].Name == configfile.ConfDefaultName {
			dupe = i
		}
	}
	if dupe >= 0 {
		// Warn the user loudly: The gocryptfs.conf_NAME_COLLISION file will
		// throw ENOENT errors that are hard to miss.
		tlog.Warn.Printf("The file %q is mapped to %q and shadows another file. Please rename %q in directory %q.",
			configfile.ConfReverseName, configfile.ConfDefaultName, configfile.ConfDefaultName, rn.args.Cipherdir)
		entries[dupe].Name = "gocryptfs.conf_NAME_COLLISION_" + fmt.Sprintf("%d", cryptocore.RandUint64())
	}
	return fs.NewListDirStream(entries), 0
}
