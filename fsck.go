package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/hanwen/go-fuse/v2/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

type fsckObj struct {
	fs *fusefrontend.FS
	// List of corrupt files
	corruptList []string
	// List of skipped files
	skippedList []string
	// Protects corruptList
	listLock sync.Mutex
	// stop a running watchMitigatedCorruptions thread
	watchDone chan struct{}
	// Inode numbers of hard-linked files (Nlink > 1) that we have already checked
	seenInodes map[uint64]struct{}
}

func runsAsRoot() bool {
	return syscall.Geteuid() == 0
}

func (ck *fsckObj) markCorrupt(path string) {
	ck.listLock.Lock()
	ck.corruptList = append(ck.corruptList, path)
	ck.listLock.Unlock()
}

func (ck *fsckObj) markSkipped(path string) {
	ck.listLock.Lock()
	ck.skippedList = append(ck.skippedList, path)
	ck.listLock.Unlock()
}

// Watch for mitigated corruptions that occur during OpenDir()
func (ck *fsckObj) watchMitigatedCorruptionsOpenDir(path string) {
	for {
		select {
		case item := <-ck.fs.MitigatedCorruptions:
			fmt.Printf("fsck: corrupt entry in dir %q: %q\n", path, item)
			ck.markCorrupt(filepath.Join(path, item))
		case <-ck.watchDone:
			return
		}
	}
}

// Recursively check dir for corruption
func (ck *fsckObj) dir(path string) {
	tlog.Debug.Printf("ck.dir %q\n", path)
	ck.xattrs(path)
	// Run OpenDir and catch transparently mitigated corruptions
	go ck.watchMitigatedCorruptionsOpenDir(path)
	entries, status := ck.fs.OpenDir(path, nil)
	ck.watchDone <- struct{}{}
	// Also catch non-mitigated corruptions
	if !status.Ok() {
		fmt.Printf("fsck: error opening dir %q: %v\n", path, status)
		if status == fuse.EACCES && !runsAsRoot() {
			ck.markSkipped(path)
		} else {
			ck.markCorrupt(path)
		}
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
			fmt.Printf("fsck: unhandled file type %x\n", filetype)
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

// Watch for mitigated corruptions that occur during Read()
func (ck *fsckObj) watchMitigatedCorruptionsRead(path string) {
	for {
		select {
		case item := <-ck.fs.MitigatedCorruptions:
			fmt.Printf("fsck: corrupt file %q (inode %s)\n", path, item)
			ck.markCorrupt(path)
		case <-ck.watchDone:
			return
		}
	}
}

// Check file for corruption
func (ck *fsckObj) file(path string) {
	tlog.Debug.Printf("ck.file %q\n", path)
	attr, status := ck.fs.GetAttr(path, nil)
	if !status.Ok() {
		ck.markCorrupt(path)
		fmt.Printf("fsck: error stating file %q: %v\n", path, status)
		return
	}
	if attr.Nlink > 1 {
		// Due to hard links, we may have already checked this file.
		if _, ok := ck.seenInodes[attr.Ino]; ok {
			tlog.Debug.Printf("ck.file : skipping %q (inode number %d already seen)\n", path, attr.Ino)
			return
		}
		ck.seenInodes[attr.Ino] = struct{}{}
	}
	ck.xattrs(path)
	f, status := ck.fs.Open(path, syscall.O_RDONLY, nil)
	if !status.Ok() {
		fmt.Printf("fsck: error opening file %q: %v\n", path, status)
		if status == fuse.EACCES && !runsAsRoot() {
			ck.markSkipped(path)
		} else {
			ck.markCorrupt(path)
		}
		return
	}
	defer f.Release()
	// 128 kiB of zeros
	allZero := make([]byte, fuse.MAX_KERNEL_WRITE)
	buf := make([]byte, fuse.MAX_KERNEL_WRITE)
	var off int64
	// Read() through the whole file and catch transparently mitigated corruptions
	go ck.watchMitigatedCorruptionsRead(path)
	defer func() { ck.watchDone <- struct{}{} }()
	for {
		tlog.Debug.Printf("ck.file: read %d bytes from offset %d\n", len(buf), off)
		result, status := f.Read(buf, off)
		if !status.Ok() {
			ck.markCorrupt(path)
			fmt.Printf("fsck: error reading file %q (inum %d): %v\n", path, inum(f), status)
			return
		}
		n := result.Size()
		// EOF
		if n == 0 {
			return
		}
		off += int64(n)
		// If we seem to be in the middle of a file hole, try to skip to the next
		// data section.
		data := buf[:n]
		if bytes.Equal(data, allZero) {
			tlog.Debug.Printf("ck.file: trying to skip file hole\n")
			f2 := f.(*fusefrontend.File)
			nextOff, err := f2.SeekData(off)
			if err == nil {
				off = nextOff
			}
		}
	}
}

// Watch for mitigated corruptions that occur during ListXAttr()
func (ck *fsckObj) watchMitigatedCorruptionsListXAttr(path string) {
	for {
		select {
		case item := <-ck.fs.MitigatedCorruptions:
			fmt.Printf("fsck: corrupt xattr name on file %q: %q\n", path, item)
			ck.markCorrupt(path + " xattr:" + item)
		case <-ck.watchDone:
			return
		}
	}
}

// Check xattrs on file/dir at path
func (ck *fsckObj) xattrs(path string) {
	// Run ListXAttr() and catch transparently mitigated corruptions
	go ck.watchMitigatedCorruptionsListXAttr(path)
	attrs, status := ck.fs.ListXAttr(path, nil)
	ck.watchDone <- struct{}{}
	// Also catch non-mitigated corruptions
	if !status.Ok() {
		fmt.Printf("fsck: error listing xattrs on %q: %v\n", path, status)
		ck.markCorrupt(path)
		return
	}
	for _, a := range attrs {
		_, status := ck.fs.GetXAttr(path, a, nil)
		if !status.Ok() {
			fmt.Printf("fsck: error reading xattr %q from %q: %v\n", a, path, status)
			if status == fuse.EACCES && !runsAsRoot() {
				ck.markSkipped(path)
			} else {
				ck.markCorrupt(path)
			}
		}
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
	fs.MitigatedCorruptions = make(chan string)
	ck := fsckObj{
		fs:         fs,
		watchDone:  make(chan struct{}),
		seenInodes: make(map[uint64]struct{}),
	}
	ck.dir("")
	wipeKeys()
	if len(ck.corruptList) == 0 && len(ck.skippedList) == 0 {
		tlog.Info.Printf("fsck summary: no problems found\n")
		return
	}
	if len(ck.skippedList) > 0 {
		tlog.Warn.Printf("fsck: re-run this program as root to check all files!\n")
	}
	fmt.Printf("fsck summary: %d corrupt files, %d files skipped\n", len(ck.corruptList), len(ck.skippedList))
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

func inum(f nodefs.File) uint64 {
	var a fuse.Attr
	f.GetAttr(&a)
	return a.Ino
}
