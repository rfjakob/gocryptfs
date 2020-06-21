package fusefrontend

import (
	"context"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

func (n *Node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	rn := n.rootNode()
	p := n.path()
	dirName := filepath.Base(p)
	parentDirFd, cDirName, err := rn.openBackingDir(p)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(parentDirFd)

	// Read ciphertext directory
	var cipherEntries []fuse.DirEntry
	fd, err := syscallcompat.Openat(parentDirFd, cDirName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	defer syscall.Close(fd)
	cipherEntries, err = syscallcompat.Getdents(fd)
	if err != nil {
		return nil, fs.ToErrno(err)
	}
	// Get DirIV (stays nil if PlaintextNames is used)
	var cachedIV []byte
	if !rn.args.PlaintextNames {
		// Read the DirIV from disk
		cachedIV, err = nametransform.ReadDirIVAt(fd)
		if err != nil {
			tlog.Warn.Printf("OpenDir %q: could not read %s: %v", cDirName, nametransform.DirIVFilename, err)
			return nil, syscall.EIO
		}
	}
	// Decrypted directory entries
	var plain []fuse.DirEntry
	// Filter and decrypt filenames
	for i := range cipherEntries {
		cName := cipherEntries[i].Name
		if dirName == "." && cName == configfile.ConfDefaultName {
			// silently ignore "gocryptfs.conf" in the top level dir
			continue
		}
		if rn.args.PlaintextNames {
			plain = append(plain, cipherEntries[i])
			continue
		}
		if cName == nametransform.DirIVFilename {
			// silently ignore "gocryptfs.diriv" everywhere if dirIV is enabled
			continue
		}
		// Handle long file name
		isLong := nametransform.LongNameNone
		if rn.args.LongNames {
			isLong = nametransform.NameType(cName)
		}
		if isLong == nametransform.LongNameContent {
			cNameLong, err := nametransform.ReadLongNameAt(fd, cName)
			if err != nil {
				tlog.Warn.Printf("OpenDir %q: invalid entry %q: Could not read .name: %v",
					cDirName, cName, err)
				rn.reportMitigatedCorruption(cName)
				continue
			}
			cName = cNameLong
		} else if isLong == nametransform.LongNameFilename {
			// ignore "gocryptfs.longname.*.name"
			continue
		}
		name, err := rn.nameTransform.DecryptName(cName, cachedIV)
		if err != nil {
			tlog.Warn.Printf("OpenDir %q: invalid entry %q: %v",
				cDirName, cName, err)
			rn.reportMitigatedCorruption(cName)
			continue
		}
		// Override the ciphertext name with the plaintext name but reuse the rest
		// of the structure
		cipherEntries[i].Name = name
		plain = append(plain, cipherEntries[i])
	}

	return fs.NewListDirStream(plain), 0
}
