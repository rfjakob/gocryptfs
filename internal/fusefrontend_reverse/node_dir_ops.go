package fusefrontend_reverse

import (
	"context"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
)

// Readdir - FUSE call.
//
// This function is symlink-safe through use of openBackingDir() and
// ReadDirIVAt().
func (n *Node) Readdir(ctx context.Context) (stream fs.DirStream, errno syscall.Errno) {
	dirfd, cName, errno := n.prepareAtSyscall("")
	if errno != 0 {
		return
	}
	defer syscall.Close(dirfd)

	// Read plaintext directory
	var entries []fuse.DirEntry
	fd, err := syscallcompat.Openat(dirfd, cName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(fd)
	entries, err = syscallcompat.Getdents(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}

	rn := n.rootNode()
	if rn.args.PlaintextNames {
		panic("todo")
	}

	// Filter out excluded entries
	//TODO
	//entries = rfs.excludeDirEntries(relPath, entries)

	// Virtual files: at least one gocryptfs.diriv file
	virtualFiles := []fuse.DirEntry{
		{Mode: virtualFileMode, Name: nametransform.DirIVFilename},
	}

	cipherPath := n.Path()
	dirIV := pathiv.Derive(cipherPath, pathiv.PurposeDirIV)
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
