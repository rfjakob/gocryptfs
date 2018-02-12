package fusefrontend_reverse

import (
	"log"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// File names are padded to 16-byte multiples, encrypted and
	// base64-encoded. We can encode at most 176 bytes to stay below the 255
	// bytes limit:
	// * base64(176 bytes) = 235 bytes
	// * base64(192 bytes) = 256 bytes (over 255!)
	// But the PKCS#7 padding is at least one byte. This means we can only use
	// 175 bytes for the file name.
	shortNameMax = 175
)

// longnameParentCache maps dir+"/"+longname to plaintextname.
// Yes, the combination of relative plaintext dir path and encrypted
// longname is strange, but works fine as a map index.
var longnameParentCache map[string]string
var longnameCacheLock sync.Mutex

// Very simple cache cleaner: Nuke it every hour
func longnameCacheCleaner() {
	for {
		time.Sleep(time.Hour)
		longnameCacheLock.Lock()
		longnameParentCache = map[string]string{}
		longnameCacheLock.Unlock()
	}
}

func initLongnameCache() {
	if longnameParentCache != nil {
		return
	}
	longnameParentCache = map[string]string{}
	go longnameCacheCleaner()
}

// findLongnameParent converts "longname" = "gocryptfs.longname.XYZ" to the
// plaintext name. "dir" = relative plaintext path to the directory the
// longname file is in, "dirIV" = directory IV of the directory.
func (rfs *ReverseFS) findLongnameParent(dir string, dirIV []byte, longname string) (plaintextName string, err error) {
	longnameCacheLock.Lock()
	hit := longnameParentCache[dir+"/"+longname]
	longnameCacheLock.Unlock()
	if hit != "" {
		return hit, nil
	}
	fd, err := syscallcompat.OpenNofollow(rfs.args.Cipherdir, dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		tlog.Warn.Printf("findLongnameParent: opendir failed: %v\n", err)
		return "", err
	}
	dirEntries, err := syscallcompat.Getdents(fd)
	unix.Close(fd)
	if err != nil {
		tlog.Warn.Printf("findLongnameParent: Getdents failed: %v\n", err)
		return "", err
	}
	longnameCacheLock.Lock()
	defer longnameCacheLock.Unlock()
	for _, entry := range dirEntries {
		plaintextName := entry.Name
		if len(plaintextName) <= shortNameMax {
			continue
		}
		cName := rfs.nameTransform.EncryptName(plaintextName, dirIV)
		if len(cName) <= unix.NAME_MAX {
			// Entry should have been skipped by the "continue" above
			log.Panic("logic error or wrong shortNameMax constant?")
		}
		hName := rfs.nameTransform.HashLongName(cName)
		longnameParentCache[dir+"/"+hName] = plaintextName
		if longname == hName {
			hit = plaintextName
		}
	}
	if hit == "" {
		return "", unix.ENOENT
	}
	return hit, nil
}

func (rfs *ReverseFS) newNameFile(relPath string) (nodefs.File, fuse.Status) {
	dotName := filepath.Base(relPath)                                    // gocryptfs.longname.XYZ.name
	longname := dotName[:len(dotName)-len(nametransform.LongNameSuffix)] // gocryptfs.longname.XYZ
	// cipher directory
	cDir := nametransform.Dir(relPath)
	// plain directory
	pDir, err := rfs.decryptPath(cDir)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	dirIV := pathiv.Derive(cDir, pathiv.PurposeDirIV)
	// plain name
	pName, err := rfs.findLongnameParent(pDir, dirIV, longname)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	content := []byte(rfs.nameTransform.EncryptName(pName, dirIV))
	parentFile := filepath.Join(pDir, pName)
	return rfs.newVirtualFile(content, rfs.args.Cipherdir, parentFile, inoBaseNameFile)
}
