package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

type fsckObj struct {
	fs *fusefrontend.FS
	// List of corrupt files
	corruptList []string
}

func (ck *fsckObj) markCorrupt(path string) {
	ck.corruptList = append(ck.corruptList, path)
}

// Recursively check dir for corruption
func (ck *fsckObj) dir(path string) {
	//fmt.Printf("ck.dir %q\n", path)
	entries, status := ck.fs.OpenDir(path, nil)
	if !status.Ok() {
		ck.markCorrupt(path)
		fmt.Printf("fsck: error opening dir %q: %v\n", path, status)
		return
	}
	// Sort alphabetically
	sort.Sort(sortableDirEntries(entries))
	for _, entry := range entries {
		if entry.Name == "." || entry.Name == ".." {
			continue
		}
		nextPath := filepath.Join(path, entry.Name)
		filetype := entry.Mode & syscall.S_IFMT
		//fmt.Printf("  %q %x\n", entry.Name, entry.Mode)
		switch filetype {
		case syscall.S_IFDIR:
			ck.dir(nextPath)
		case syscall.S_IFREG:
			ck.file(nextPath)
		case syscall.S_IFLNK:
			ck.symlink(nextPath)
		case syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFBLK, syscall.S_IFCHR:
			// nothing to check
		default:
			fmt.Printf("fsck: unhandle file type %x\n", filetype)
		}
	}
}

func (ck *fsckObj) symlink(path string) {
	_, status := ck.fs.Readlink(path, nil)
	if !status.Ok() {
		ck.markCorrupt(path)
		fmt.Printf("fsck: error reading symlink %q: %v\n", path, status)
	}
}

// check file for corruption
func (ck *fsckObj) file(path string) {
	//fmt.Printf("ck.file %q\n", path)
	f, status := ck.fs.Open(path, syscall.O_RDONLY, nil)
	if !status.Ok() {
		ck.markCorrupt(path)
		fmt.Printf("fsck: error opening file %q: %v\n", path, status)
		return
	}
	defer f.Release()
	buf := make([]byte, fuse.MAX_KERNEL_WRITE)
	var off int64
	for {
		result, status := f.Read(buf, off)
		if !status.Ok() {
			ck.markCorrupt(path)
			fmt.Printf("fsck: error reading file %q at offset %d: %v\n", path, off, status)
			return
		}
		// EOF
		if result.Size() == 0 {
			return
		}
		off += int64(result.Size())
	}
}

func fsck(args *argContainer) {
	if args.reverse {
		tlog.Fatal.Printf("Running -fsck with -reverse is not supported")
		os.Exit(exitcodes.Usage)
	}
	args.allow_other = false
	pfs, wipeKeys := initFuseFrontend(args)
	fs := pfs.(*fusefrontend.FS)
	ck := fsckObj{
		fs: fs,
	}
	ck.dir("")
	wipeKeys()
	if len(ck.corruptList) == 0 {
		fmt.Printf("fsck summary: no problems found")
		return
	}
	fmt.Printf("fsck summary: found %d corrupt files:\n", len(ck.corruptList))
	for _, path := range ck.corruptList {
		fmt.Printf("  %q\n", path)
	}
	os.Exit(exitcodes.FsckErrors)
}

type sortableDirEntries []fuse.DirEntry

func (s sortableDirEntries) Len() int {
	return len(s)
}

func (s sortableDirEntries) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortableDirEntries) Less(i, j int) bool {
	return strings.Compare(s[i].Name, s[j].Name) < 0
}
