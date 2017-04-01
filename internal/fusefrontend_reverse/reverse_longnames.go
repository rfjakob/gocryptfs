package fusefrontend_reverse

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	shortNameMax = 176
)

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

// findLongnameParent converts "gocryptfs.longname.XYZ" to the plaintext name
func (rfs *ReverseFS) findLongnameParent(dir string, dirIV []byte, longname string) (plaintextName string, err error) {
	longnameCacheLock.Lock()
	hit := longnameParentCache[longname]
	longnameCacheLock.Unlock()
	if hit != "" {
		return hit, nil
	}
	absDir := filepath.Join(rfs.args.Cipherdir, dir)
	dirfd, err := os.Open(absDir)
	if err != nil {
		tlog.Warn.Printf("findLongnameParent: opendir failed: %v\n", err)
		return "", err
	}
	dirEntries, err := dirfd.Readdirnames(-1)
	if err != nil {
		return "", err
	}
	longnameCacheLock.Lock()
	defer longnameCacheLock.Unlock()
	for _, plaintextName = range dirEntries {
		if len(plaintextName) <= shortNameMax {
			continue
		}
		cName := rfs.nameTransform.EncryptName(plaintextName, dirIV)
		if len(cName) <= syscall.NAME_MAX {
			log.Panic("logic error or wrong shortNameMax constant?")
		}
		hName := rfs.nameTransform.HashLongName(cName)
		longnameParentCache[hName] = plaintextName
		if longname == hName {
			hit = plaintextName
		}
	}
	if hit == "" {
		return "", syscall.ENOENT
	}

	return hit, nil
}

func (rfs *ReverseFS) newNameFile(relPath string) (nodefs.File, fuse.Status) {
	dotName := filepath.Base(relPath)                                    // gocryptfs.longname.XYZ.name
	longname := dotName[:len(dotName)-len(nametransform.LongNameSuffix)] // gocryptfs.longname.XYZ
	// cipher directory
	cDir := saneDir(relPath)
	// plain directory
	pDir, err := rfs.decryptPath(cDir)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	dirIV := derivePathIV(cDir, ivPurposeDirIV)
	// plain name
	pName, err := rfs.findLongnameParent(pDir, dirIV, longname)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	content := []byte(rfs.nameTransform.EncryptName(pName, dirIV))
	parentFile := filepath.Join(rfs.args.Cipherdir, pDir, pName)
	return rfs.newVirtualFile(content, parentFile)
}
