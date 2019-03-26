package fusefrontend_reverse

import (
	"fmt"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"

	"github.com/sabhiram/go-gitignore"
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
	nameTransform nametransform.NameTransformer
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// Tests wheter a path is excluded (hiden) from the user. Used by -exclude.
	excluder ignore.IgnoreParser
}

var _ pathfs.FileSystem = &ReverseFS{}

// NewFS returns an encrypted FUSE overlay filesystem.
// In this case (reverse mode) the backing directory is plain-text and
// ReverseFS provides an encrypted view.
func NewFS(args fusefrontend.Args, c *contentenc.ContentEnc, n nametransform.NameTransformer) *ReverseFS {
	initLongnameCache()
	fs := &ReverseFS{
		// pathfs.defaultFileSystem returns ENOSYS for all operations
		FileSystem:    pathfs.NewDefaultFileSystem(),
		loopbackfs:    pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:          args,
		nameTransform: n,
		contentEnc:    c,
	}
	fs.prepareExcluder(args)
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

// getFileInfo returns information on a ciphertext path "relPath":
// - ftype: file type (as returned by getFileType)
// - excluded: if the path is excluded
// - pPath: if it's not a special file, the decrypted path
// - err: non nil if any error happens
func (rfs *ReverseFS) getFileInfo(relPath string) (ftype fileType, excluded bool, pPath string, err error) {
	ftype = rfs.getFileType(relPath)
	if ftype == typeConfig {
		excluded, pPath, err = false, "", nil
		return
	}
	if ftype == typeDiriv {
		parentDir := nametransform.Dir(relPath)
		_, excluded, _, err = rfs.getFileInfo(parentDir)
		pPath = ""
		return
	}
	if ftype == typeName {
		parentDir := nametransform.Dir(relPath)
		var parentExcluded bool
		_, parentExcluded, _, err = rfs.getFileInfo(parentDir)
		if parentExcluded || err != nil {
			excluded, pPath = parentExcluded, ""
			return
		}
		relPath = nametransform.RemoveLongNameSuffix(relPath)
	}
	pPath, err = rfs.decryptPath(relPath)
	excluded = err == nil && rfs.isExcludedPlain(pPath)
	return
}

type fileType int

// Values returned by getFileType
const (
	// A regular file/directory/symlink
	typeRegular fileType = iota
	// A DirIV (gocryptfs.diriv) file
	typeDiriv
	// A .name file for a file with a long name
	typeName
	// The config file
	typeConfig
)

// getFileType returns the type of file. Only the name is checked
func (rfs *ReverseFS) getFileType(cPath string) fileType {
	if rfs.isDirIV(cPath) {
		return typeDiriv
	}
	if rfs.isNameFile(cPath) {
		return typeName
	}
	if rfs.isTranslatedConfig(cPath) {
		return typeConfig
	}
	return typeRegular
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
	ftype, excluded, pPath, err := rfs.getFileInfo(relPath)
	if excluded {
		return nil, fuse.ENOENT
	}
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Handle "gocryptfs.conf"
	if ftype == typeConfig {
		absConfPath, _ := rfs.abs(configfile.ConfReverseName, nil)
		var st syscall.Stat_t
		err = syscall.Lstat(absConfPath, &st)
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
	if ftype == typeDiriv {
		virtual = true
		f, status = rfs.newDirIVFile(relPath)
	}
	if ftype == typeName {
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
	dirfd, name, err := rfs.openBackingDir(pPath)
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
	ftype, excluded, pPath, err := rfs.getFileInfo(relPath)
	if excluded {
		return fuse.ENOENT
	}
	if err != nil {
		return fuse.ToStatus(err)
	}
	if ftype != typeRegular {
		// access(2) R_OK flag for checking if the file is readable, always 4 as defined in POSIX.
		ROK := uint32(0x4)
		// Virtual files can always be read and never written
		if mode == ROK || mode == 0 {
			return fuse.OK
		}
		return fuse.EPERM
	}
	dirfd, name, err := rfs.openBackingDir(pPath)
	if err != nil {
		return fuse.ToStatus(err)
	}
	err = syscallcompat.Faccessat(dirfd, name, mode)
	syscall.Close(dirfd)
	return fuse.ToStatus(err)
}

// Open - FUSE call
func (rfs *ReverseFS) Open(relPath string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	ftype, excluded, pPath, err := rfs.getFileInfo(relPath)
	if excluded {
		return nil, fuse.ENOENT
	}
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	if ftype == typeConfig {
		return rfs.loopbackfs.Open(configfile.ConfReverseName, flags, context)
	}
	if ftype == typeDiriv {
		return rfs.newDirIVFile(relPath)
	}
	if ftype == typeName {
		return rfs.newNameFile(relPath)
	}
	return rfs.newFile(relPath, pPath)
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
		tlog.Warn.Printf("The file %q is mapped to %q and shadows another file. Please rename %q in directory %q.",
			configfile.ConfReverseName, configfile.ConfDefaultName, configfile.ConfDefaultName, rfs.args.Cipherdir)
		entries[dupe].Name = "gocryptfs.conf_NAME_COLLISION_" + fmt.Sprintf("%d", cryptocore.RandUint64())
	}
	return entries, status
}

// OpenDir - FUSE readdir call
func (rfs *ReverseFS) OpenDir(cipherPath string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	ftype, excluded, relPath, err := rfs.getFileInfo(cipherPath)
	if excluded {
		return nil, fuse.ENOENT
	}
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	if ftype != typeRegular {
		return nil, fuse.ENOTDIR
	}
	// Read plaintext dir
	dirfd, err := syscallcompat.OpenDirNofollow(rfs.args.Cipherdir, filepath.Dir(relPath))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	fd, err := syscallcompat.Openat(dirfd, filepath.Base(relPath), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	syscall.Close(dirfd)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	entries, err := syscallcompat.Getdents(fd)
	syscall.Close(fd)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	if rfs.args.PlaintextNames {
		var status fuse.Status
		entries, status = rfs.openDirPlaintextnames(cipherPath, entries)
		if !status.Ok() {
			return nil, status
		}
		entries = rfs.excludeDirEntries(relPath, entries)
		return entries, fuse.OK
	}
	// Filter out excluded entries
	entries = rfs.excludeDirEntries(relPath, entries)
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
		if cipherPath == "" && entries[i].Name == configfile.ConfReverseName &&
			!rfs.args.ConfigCustom {
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
	// Add virtual files
	entries = append(entries, virtualFiles[:nVirtual]...)
	return entries, fuse.OK
}

// excludeDirEntries filters out directory entries that are "-exclude"d.
// pDir is the relative plaintext path to the directory these entries are
// from. The entries should be plaintext files.
func (rfs *ReverseFS) excludeDirEntries(pDir string, entries []fuse.DirEntry) (filtered []fuse.DirEntry) {
	if rfs.excluder == nil {
		return entries
	}
	filtered = make([]fuse.DirEntry, 0, len(entries))
	for _, entry := range entries {
		// filepath.Join handles the case of pDir="" correctly:
		// Join("", "foo") -> "foo". This does not: pDir + "/" + name"
		p := filepath.Join(pDir, entry.Name)
		if rfs.isExcludedPlain(p) {
			// Skip file
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

// StatFs - FUSE call. Returns information about the filesystem (free space
// etc).
// Securing statfs against symlink races seems to be more trouble than
// it's worth, so we just ignore the path and always return info about the
// backing storage root dir.
func (rfs *ReverseFS) StatFs(relPath string) *fuse.StatfsOut {
	_, excluded, _, err := rfs.getFileInfo(relPath)
	if excluded || err != nil {
		return nil
	}
	var s syscall.Statfs_t
	err = syscall.Statfs(rfs.args.Cipherdir, &s)
	if err != nil {
		return nil
	}
	out := &fuse.StatfsOut{}
	out.FromStatfsT(&s)
	return out
}

// Readlink - FUSE call
func (rfs *ReverseFS) Readlink(relPath string, context *fuse.Context) (string, fuse.Status) {
	ftype, excluded, pPath, err := rfs.getFileInfo(relPath)
	if excluded {
		return "", fuse.ENOENT
	}
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	if ftype != typeRegular {
		return "", fuse.EINVAL
	}
	dirfd, name, err := rfs.openBackingDir(pPath)
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
	cTarget := rfs.nameTransform.B64EncodeToString(cBinTarget)
	// The kernel will reject a symlink target above 4096 chars and return
	// and I/O error to the user. Better emit the proper error ourselves.
	if len(cTarget) > syscallcompat.PATH_MAX {
		return "", fuse.Status(syscall.ENAMETOOLONG)
	}
	return cTarget, fuse.OK
}
