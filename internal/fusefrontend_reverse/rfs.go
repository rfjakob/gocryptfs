package fusefrontend_reverse

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// ReverseFS implements the pathfs.FileSystem interface and provides an
// encrypted view of a plaintext directory.
type ReverseFS struct {
	// Embed pathfs.defaultFileSystem for a ENOSYS implementation of all methods
	pathfs.FileSystem
	// pathfs.loopbackFileSystem, see go-fuse/fuse/pathfs/loopback.go
	loopbackfs pathfs.FileSystem
	// Stores configuration arguments
	args fusefrontend.Args
	// Filename encryption helper
	nameTransform *nametransform.NameTransform
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// Relative ciphertext paths to exclude (hide) from the user. Used by -exclude.
	cExclude []string
}

var _ pathfs.FileSystem = &ReverseFS{}

// NewFS returns an encrypted FUSE overlay filesystem.
// In this case (reverse mode) the backing directory is plain-text and
// ReverseFS provides an encrypted view.
func NewFS(args fusefrontend.Args, c *contentenc.ContentEnc, n *nametransform.NameTransform) *ReverseFS {
	initLongnameCache()
	fs := &ReverseFS{
		// pathfs.defaultFileSystem returns ENOSYS for all operations
		FileSystem:    pathfs.NewDefaultFileSystem(),
		loopbackfs:    pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:          args,
		nameTransform: n,
		contentEnc:    c,
	}
	if len(args.Exclude) > 0 {
		for _, dirty := range args.Exclude {
			clean := ctlsock.SanitizePath(dirty)
			if clean != dirty {
				tlog.Warn.Printf("-exclude: non-canonical path %q has been interpreted as %q", dirty, clean)
			}
			cPath, err := fs.EncryptPath(clean)
			if err != nil {
				tlog.Fatal.Printf("-exclude: EncryptPath %q failed: %v", clean, err)
				os.Exit(exitcodes.ExcludeError)
			}
			fs.cExclude = append(fs.cExclude, cPath)
		}
		tlog.Debug.Printf("-exclude: %v -> %v", fs.args.Exclude, fs.cExclude)
	}
	return fs
}

// relDir is identical to filepath.Dir excepts that it returns "" when
// filepath.Dir would return ".".
// In the FUSE API, the root directory is called "", and we actually want that.
func relDir(path string) string {
	dir := filepath.Dir(path)
	if dir == "." {
		return ""
	}
	return dir
}

// isExcluded finds out if relative ciphertext path "relPath" is excluded
// (used when -exclude is passed by the user)
func (rfs *ReverseFS) isExcluded(relPath string) bool {
	for _, e := range rfs.cExclude {
		if e == relPath {
			return true
		}
		// Files inside an excluded directory are also excluded
		if strings.HasPrefix(relPath, e+"/") {
			return true
		}
	}
	return false
}

// isDirIV determines if the path points to a gocryptfs.diriv file
func (rfs *ReverseFS) isDirIV(relPath string) bool {
	if rfs.args.PlaintextNames {
		return false
	}
	return filepath.Base(relPath) == nametransform.DirIVFilename
}

// isNameFile determines if the path points to a gocryptfs.longname.*.name
// file
func (rfs *ReverseFS) isNameFile(relPath string) bool {
	if rfs.args.PlaintextNames {
		return false
	}
	fileType := nametransform.NameType(filepath.Base(relPath))
	return fileType == nametransform.LongNameFilename
}

// isTranslatedConfig returns true if the default config file name is in use
// and the ciphertext path is "gocryptfs.conf".
// "gocryptfs.conf" then maps to ".gocryptfs.reverse.conf" in the plaintext
// directory.
func (rfs *ReverseFS) isTranslatedConfig(relPath string) bool {
	if rfs.args.ConfigCustom {
		return false
	}
	if relPath == configfile.ConfDefaultName {
		return true
	}
	return false
}

// GetAttr - FUSE call
// "relPath" is the relative ciphertext path
func (rfs *ReverseFS) GetAttr(relPath string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	if rfs.isExcluded(relPath) {
		return nil, fuse.ENOENT
	}
	// Handle "gocryptfs.conf"
	if rfs.isTranslatedConfig(relPath) {
		absConfPath, _ := rfs.abs(configfile.ConfReverseName, nil)
		var st syscall.Stat_t
		err := syscall.Lstat(absConfPath, &st)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
		var a fuse.Attr
		a.FromStat(&st)
		if rfs.args.ForceOwner != nil {
			a.Owner = *rfs.args.ForceOwner
		}
		return &a, fuse.OK
	}
	// Handle virtual files (gocryptfs.diriv, *.name)
	var f nodefs.File
	var status fuse.Status
	virtual := false
	if rfs.isDirIV(relPath) {
		virtual = true
		f, status = rfs.newDirIVFile(relPath)
	}
	if rfs.isNameFile(relPath) {
		virtual = true
		f, status = rfs.newNameFile(relPath)
	}
	if virtual {
		if !status.Ok() {
			tlog.Warn.Printf("GetAttr %q: newXFile failed: %v\n", relPath, status)
			return nil, status
		}
		var a fuse.Attr
		status = f.GetAttr(&a)
		if rfs.args.ForceOwner != nil {
			a.Owner = *rfs.args.ForceOwner
		}
		return &a, status
	}
	dirfd, name, err := rfs.openBackingDir(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Stat the backing file/dir using Fstatat
	var st unix.Stat_t
	err = syscallcompat.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	syscall.Close(dirfd)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Instead of risking an inode number collision, we return an error.
	if st.Ino > inoBaseMin {
		tlog.Warn.Printf("GetAttr %q: backing file inode number %d crosses reserved space, max=%d. Returning EOVERFLOW.",
			relPath, st.Ino, inoBaseMin)
		return nil, fuse.ToStatus(syscall.EOVERFLOW)
	}
	var a fuse.Attr
	st2 := syscallcompat.Unix2syscall(st)
	a.FromStat(&st2)
	// Calculate encrypted file size
	if a.IsRegular() {
		a.Size = rfs.contentEnc.PlainSizeToCipherSize(a.Size)
	} else if a.IsSymlink() {
		var linkTarget string
		var readlinkStatus fuse.Status

		linkTarget, readlinkStatus = rfs.Readlink(relPath, context)
		if !readlinkStatus.Ok() {
			return nil, readlinkStatus
		}

		a.Size = uint64(len(linkTarget))
	}
	if rfs.args.ForceOwner != nil {
		a.Owner = *rfs.args.ForceOwner
	}
	return &a, fuse.OK
}

// Access - FUSE call
func (rfs *ReverseFS) Access(relPath string, mode uint32, context *fuse.Context) fuse.Status {
	if rfs.isExcluded(relPath) {
		return fuse.ENOENT
	}
	if rfs.isTranslatedConfig(relPath) || rfs.isDirIV(relPath) || rfs.isNameFile(relPath) {
		// access(2) R_OK flag for checking if the file is readable, always 4 as defined in POSIX.
		ROK := uint32(0x4)
		// Virtual files can always be read and never written
		if mode == ROK || mode == 0 {
			return fuse.OK
		}
		return fuse.EPERM
	}
	dirfd, name, err := rfs.openBackingDir(relPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	err = syscallcompat.Faccessat(dirfd, name, mode)
	if err != nil {
		fmt.Printf("name=%q err=%v", name, err)
	}
	syscall.Close(dirfd)
	return fuse.ToStatus(err)
}

// Open - FUSE call
func (rfs *ReverseFS) Open(relPath string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	if rfs.isExcluded(relPath) {
		return nil, fuse.ENOENT
	}
	if rfs.isTranslatedConfig(relPath) {
		return rfs.loopbackfs.Open(configfile.ConfReverseName, flags, context)
	}
	if rfs.isDirIV(relPath) {
		return rfs.newDirIVFile(relPath)
	}
	if rfs.isNameFile(relPath) {
		return rfs.newNameFile(relPath)
	}
	return rfs.newFile(relPath)
}

func (rfs *ReverseFS) openDirPlaintextnames(relPath string, entries []fuse.DirEntry) ([]fuse.DirEntry, fuse.Status) {
	if relPath != "" || rfs.args.ConfigCustom {
		return entries, fuse.OK
	}
	// We are in the root dir and the default config file name
	// ".gocryptfs.reverse.conf" is used. We map it to "gocryptfs.conf".
	dupe := -1
	status := fuse.OK
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
		tlog.Warn.Printf("The file %s is mapped to %s and shadows another file. Please rename %s in %s .",
			configfile.ConfReverseName, configfile.ConfDefaultName, configfile.ConfDefaultName, rfs.args.Cipherdir)
		entries[dupe].Name = "gocryptfs.conf_NAME_COLLISION_" + fmt.Sprintf("%d", cryptocore.RandUint64())
	}
	return entries, status
}

// OpenDir - FUSE readdir call
func (rfs *ReverseFS) OpenDir(cipherPath string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	if rfs.isExcluded(cipherPath) {
		return nil, fuse.ENOENT
	}
	relPath, err := rfs.decryptPath(cipherPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Read plaintext dir
	fd, err := syscallcompat.OpenNofollow(rfs.args.Cipherdir, relPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	entries, err := syscallcompat.Getdents(fd)
	syscall.Close(fd)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	if rfs.args.PlaintextNames {
		return rfs.openDirPlaintextnames(cipherPath, entries)
	}
	// Allocate maximum possible number of virtual files.
	// If all files have long names we need a virtual ".name" file for each,
	// plus one for gocryptfs.diriv.
	virtualFiles := make([]fuse.DirEntry, len(entries)+1)
	// Virtual gocryptfs.diriv file
	virtualFiles[0] = fuse.DirEntry{
		Mode: virtualFileMode,
		Name: nametransform.DirIVFilename,
	}
	// Actually used entries
	nVirtual := 1

	// Encrypt names
	dirIV := pathiv.Derive(cipherPath, pathiv.PurposeDirIV)
	for i := range entries {
		var cName string
		// ".gocryptfs.reverse.conf" in the root directory is mapped to "gocryptfs.conf"
		if cipherPath == "" && entries[i].Name == configfile.ConfReverseName {
			cName = configfile.ConfDefaultName
		} else {
			cName = rfs.nameTransform.EncryptName(entries[i].Name, dirIV)
			if len(cName) > unix.NAME_MAX {
				cName = rfs.nameTransform.HashLongName(cName)
				dotNameFile := fuse.DirEntry{
					Mode: virtualFileMode,
					Name: cName + nametransform.LongNameSuffix,
				}
				virtualFiles[nVirtual] = dotNameFile
				nVirtual++
			}
		}
		entries[i].Name = cName
	}
	// Filter out excluded entries
	if rfs.cExclude != nil {
		filtered := make([]fuse.DirEntry, 0, len(entries))
		for _, entry := range entries {
			// filepath.Join handles the case of cipherPath="" correctly:
			// Join("", "foo") -> "foo". This does not: cipherPath + "/" + name"
			p := filepath.Join(cipherPath, entry.Name)
			if rfs.isExcluded(p) {
				// Skip file
				continue
			}
			filtered = append(filtered, entry)
		}
		entries = filtered
	}
	entries = append(entries, virtualFiles[:nVirtual]...)
	return entries, fuse.OK
}

// StatFs - FUSE call. Returns information about the filesystem (free space
// etc).
// Securing statfs against symlink races seems to be more trouble than
// it's worth, so we just ignore the path and always return info about the
// backing storage root dir.
func (rfs *ReverseFS) StatFs(relPath string) *fuse.StatfsOut {
	if rfs.isExcluded(relPath) {
		return nil
	}
	var s syscall.Statfs_t
	err := syscall.Statfs(rfs.args.Cipherdir, &s)
	if err != nil {
		return nil
	}
	out := &fuse.StatfsOut{}
	out.FromStatfsT(&s)
	return out
}

// Readlink - FUSE call
func (rfs *ReverseFS) Readlink(relPath string, context *fuse.Context) (string, fuse.Status) {
	if rfs.isExcluded(relPath) {
		return "", fuse.ENOENT
	}
	dirfd, name, err := rfs.openBackingDir(relPath)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	// read the link target using Readlinkat
	plainTarget, err := syscallcompat.Readlinkat(dirfd, name)
	syscall.Close(dirfd)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	if rfs.args.PlaintextNames {
		return plainTarget, fuse.OK
	}
	nonce := pathiv.Derive(relPath, pathiv.PurposeSymlinkIV)
	// Symlinks are encrypted like file contents and base64-encoded
	cBinTarget := rfs.contentEnc.EncryptBlockNonce([]byte(plainTarget), 0, nil, nonce)
	cTarget := rfs.nameTransform.B64.EncodeToString(cBinTarget)
	// The kernel will reject a symlink target above 4096 chars and return
	// and I/O error to the user. Better emit the proper error ourselves.
	if len(cTarget) > syscallcompat.PATH_MAX {
		return "", fuse.Status(syscall.ENAMETOOLONG)
	}
	return cTarget, fuse.OK
}
