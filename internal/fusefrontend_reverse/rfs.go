package fusefrontend_reverse

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
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
}

var _ pathfs.FileSystem = &ReverseFS{}

// NewFS returns an encrypted FUSE overlay filesystem.
// In this case (reverse mode) the backing directory is plain-text and
// ReverseFS provides an encrypted view.
func NewFS(args fusefrontend.Args) *ReverseFS {
	if args.CryptoBackend != cryptocore.BackendAESSIV {
		log.Panic("reverse mode must use AES-SIV, everything else is insecure")
	}
	initLongnameCache()
	cryptoCore := cryptocore.New(args.Masterkey, args.CryptoBackend, contentenc.DefaultIVBits, args.HKDF, false)
	contentEnc := contentenc.New(cryptoCore, contentenc.DefaultBS, false)
	nameTransform := nametransform.New(cryptoCore.EMECipher, args.LongNames, args.Raw64)

	return &ReverseFS{
		// pathfs.defaultFileSystem returns ENOSYS for all operations
		FileSystem:    pathfs.NewDefaultFileSystem(),
		loopbackfs:    pathfs.NewLoopbackFileSystem(args.Cipherdir),
		args:          args,
		nameTransform: nameTransform,
		contentEnc:    contentEnc,
	}
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
	// Decrypt path to "plaintext relative path"
	pRelPath, err := rfs.decryptPath(relPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	absPath, _ := rfs.abs(pRelPath, nil)
	// Stat the backing file
	var st syscall.Stat_t
	if relPath == "" {
		// Look through symlinks for the root dir
		err = syscall.Stat(absPath, &st)
	} else {
		err = syscall.Lstat(absPath, &st)
	}
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Instead of risking an inode number collision, we return an error.
	if st.Ino > virtualInoBase {
		tlog.Warn.Printf("GetAttr %q: backing file inode number %d crosses reserved space, max=%d. Returning EOVERFLOW.",
			relPath, st.Ino, virtualInoBase)
		return nil, fuse.ToStatus(syscall.EOVERFLOW)
	}
	var a fuse.Attr
	a.FromStat(&st)
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
	if rfs.isTranslatedConfig(relPath) || rfs.isDirIV(relPath) || rfs.isNameFile(relPath) {
		// access(2) R_OK flag for checking if the file is readable, always 4 as defined in POSIX.
		ROK := uint32(0x4)
		// Virtual files can always be read and never written
		if mode == ROK || mode == 0 {
			return fuse.OK
		}
		return fuse.EPERM
	}
	absPath, err := rfs.abs(rfs.decryptPath(relPath))
	if err != nil {
		return fuse.ToStatus(err)
	}
	return fuse.ToStatus(syscall.Access(absPath, mode))
}

// Open - FUSE call
func (rfs *ReverseFS) Open(relPath string, flags uint32, context *fuse.Context) (fuseFile nodefs.File, status fuse.Status) {
	if rfs.isTranslatedConfig(relPath) {
		return rfs.loopbackfs.Open(configfile.ConfReverseName, flags, context)
	}
	if rfs.isDirIV(relPath) {
		return rfs.newDirIVFile(relPath)
	}
	if rfs.isNameFile(relPath) {
		return rfs.newNameFile(relPath)
	}
	return rfs.newFile(relPath, flags)
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
	relPath, err := rfs.decryptPath(cipherPath)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	// Read plaintext dir
	entries, status := rfs.loopbackfs.OpenDir(relPath, context)
	if entries == nil {
		return nil, status
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
			if len(cName) > syscall.NAME_MAX {
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
	entries = append(entries, virtualFiles[:nVirtual]...)
	return entries, fuse.OK
}

// StatFs - FUSE call
func (rfs *ReverseFS) StatFs(name string) *fuse.StatfsOut {
	return rfs.loopbackfs.StatFs(name)
}

// Readlink - FUSE call
func (rfs *ReverseFS) Readlink(cipherPath string, context *fuse.Context) (string, fuse.Status) {
	absPath, err := rfs.abs(rfs.decryptPath(cipherPath))
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	plainTarget, err := os.Readlink(absPath)
	if err != nil {
		return "", fuse.ToStatus(err)
	}
	if rfs.args.PlaintextNames {
		return plainTarget, fuse.OK
	}
	nonce := pathiv.Derive(cipherPath, pathiv.PurposeSymlinkIV)
	// Symlinks are encrypted like file contents and base64-encoded
	cBinTarget := rfs.contentEnc.EncryptBlockNonce([]byte(plainTarget), 0, nil, nonce)
	cTarget := rfs.nameTransform.B64.EncodeToString(cBinTarget)
	return cTarget, fuse.OK
}
