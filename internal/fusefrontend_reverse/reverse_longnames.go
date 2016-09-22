package fusefrontend_reverse

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/nametransform"
)

const (
	shortNameMax = 176
)

func (rfs *reverseFS) findLongnameParent(dir string, dirIV []byte, longname string) (string, error) {
	absDir := filepath.Join(rfs.args.Cipherdir, dir)
	dirfd, err := os.Open(absDir)
	if err != nil {
		return "", err
	}
	dirEntries, err := dirfd.Readdirnames(-1)
	if err != nil {
		return "", err
	}
	for _, e := range dirEntries {
		if len(e) <= shortNameMax {
			continue
		}
		cName := rfs.nameTransform.EncryptName(e, dirIV)
		if len(cName) <= syscall.NAME_MAX {
			panic("logic error or wrong shortNameMax constant?")
		}
		hName := nametransform.HashLongName(cName)
		if longname == hName {
			return e, nil
		}
	}
	return "", syscall.ENOENT
}

func (rfs *reverseFS) newNameFile(relPath string) (nodefs.File, fuse.Status) {
	dotName := filepath.Base(relPath)                                    // gocryptfs.longname.XYZ.name
	longname := dotName[:len(dotName)-len(nametransform.LongNameSuffix)] // gocryptfs.longname.XYZ

	cDir := saneDir(relPath)
	pDir, err := rfs.decryptPath(cDir)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	dirIV := deriveDirIV(cDir)
	e, err := rfs.findLongnameParent(pDir, dirIV, longname)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	content := []byte(rfs.nameTransform.EncryptName(e, dirIV))
	parentFile := filepath.Join(rfs.args.Cipherdir, pDir)
	return rfs.NewVirtualFile(content, parentFile)
}
