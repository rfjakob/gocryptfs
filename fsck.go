package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

type fsckObj struct {
	rootNode *fusefrontend.RootNode
	// mnt is the mountpoint of the temporary mount
	mnt string
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
	// abort the running fsck operation? Checked in a few long-running loops.
	abort bool
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

func (ck *fsckObj) abs(relPath string) (absPath string) {
	return filepath.Join(ck.mnt, relPath)
}

// Watch for mitigated corruptions that occur during OpenDir()
func (ck *fsckObj) watchMitigatedCorruptionsOpenDir(path string) {
	for {
		select {
		case item := <-ck.rootNode.MitigatedCorruptions:
			fmt.Printf("fsck: corrupt entry in dir %q: %q\n", path, item)
			ck.markCorrupt(filepath.Join(path, item))
		case <-ck.watchDone:
			return
		}
	}
}

// Recursively check dir for corruption
func (ck *fsckObj) dir(relPath string) {
	tlog.Debug.Printf("ck.dir %q\n", relPath)
	ck.xattrs(relPath)
	// Run OpenDir and catch transparently mitigated corruptions
	go ck.watchMitigatedCorruptionsOpenDir(relPath)
	f, err := os.Open(ck.abs(relPath))
	ck.watchDone <- struct{}{}
	if err != nil {
		fmt.Printf("fsck: error opening dir %q: %v\n", relPath, err)
		if err == os.ErrPermission && !runsAsRoot() {
			ck.markSkipped(relPath)
		} else {
			ck.markCorrupt(relPath)
		}
		return
	}
	go ck.watchMitigatedCorruptionsOpenDir(relPath)
	entries, err := f.Readdirnames(0)
	ck.watchDone <- struct{}{}
	if err != nil {
		fmt.Printf("fsck: error reading dir %q: %v\n", relPath, err)
		ck.markCorrupt(relPath)
		return
	}
	// Sort alphabetically to make fsck runs deterministic
	sort.Strings(entries)
	for _, entry := range entries {
		if ck.abort {
			return
		}
		if entry == "." || entry == ".." {
			continue
		}
		nextPath := filepath.Join(relPath, entry)
		var st syscall.Stat_t
		err := syscall.Lstat(ck.abs(nextPath), &st)
		if err != nil {
			ck.markCorrupt(filepath.Join(relPath, entry))
			continue
		}
		filetype := st.Mode & syscall.S_IFMT
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

func (ck *fsckObj) symlink(relPath string) {
	_, err := os.Readlink(ck.abs(relPath))
	if err != nil {
		ck.markCorrupt(relPath)
		fmt.Printf("fsck: error reading symlink %q: %v\n", relPath, err)
	}
}

// Watch for mitigated corruptions that occur during Read()
func (ck *fsckObj) watchMitigatedCorruptionsRead(path string) {
	for {
		select {
		case item := <-ck.rootNode.MitigatedCorruptions:
			fmt.Printf("fsck: corrupt file %q (inode %s)\n", path, item)
			ck.markCorrupt(path)
		case <-ck.watchDone:
			return
		}
	}
}

// Check file for corruption
func (ck *fsckObj) file(relPath string) {
	tlog.Debug.Printf("ck.file %q\n", relPath)
	var st syscall.Stat_t
	err := syscall.Lstat(ck.abs(relPath), &st)
	if err != nil {
		ck.markCorrupt(relPath)
		fmt.Printf("fsck: error stating file %q: %v\n", relPath, err)
		return
	}
	if st.Nlink > 1 {
		// Due to hard links, we may have already checked this file.
		if _, ok := ck.seenInodes[st.Ino]; ok {
			tlog.Debug.Printf("ck.file : skipping %q (inode number %d already seen)\n", relPath, st.Ino)
			return
		}
		ck.seenInodes[st.Ino] = struct{}{}
	}
	ck.xattrs(relPath)
	f, err := os.Open(ck.abs(relPath))
	if err != nil {
		fmt.Printf("fsck: error opening file %q: %v\n", relPath, err)
		if err == os.ErrPermission && !runsAsRoot() {
			ck.markSkipped(relPath)
		} else {
			ck.markCorrupt(relPath)
		}
		return
	}
	defer f.Close()
	// 128 kiB of zeros
	allZero := make([]byte, fuse.MAX_KERNEL_WRITE)
	buf := make([]byte, fuse.MAX_KERNEL_WRITE)
	var off int64
	// Read() through the whole file and catch transparently mitigated corruptions
	go ck.watchMitigatedCorruptionsRead(relPath)
	defer func() { ck.watchDone <- struct{}{} }()
	for {
		if ck.abort {
			return
		}
		tlog.Debug.Printf("ck.file: read %d bytes from offset %d\n", len(buf), off)
		n, err := f.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			ck.markCorrupt(relPath)
			fmt.Printf("fsck: error reading file %q (inum %d): %v\n", relPath, inum(f), err)
			return
		}
		// EOF
		if err == io.EOF {
			return
		}
		off += int64(n)
		// If we seem to be in the middle of a file hole, try to skip to the next
		// data section.
		data := buf[:n]
		if bytes.Equal(data, allZero) {
			tlog.Debug.Printf("ck.file: trying to skip file hole\n")
			const SEEK_DATA = 3
			nextOff, err := syscall.Seek(int(f.Fd()), off, SEEK_DATA)
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
		case item := <-ck.rootNode.MitigatedCorruptions:
			fmt.Printf("fsck: corrupt xattr name on file %q: %q\n", path, item)
			ck.markCorrupt(path + " xattr:" + item)
		case <-ck.watchDone:
			return
		}
	}
}

// Check xattrs on file/dir at path
func (ck *fsckObj) xattrs(relPath string) {
	// Run ListXAttr() and catch transparently mitigated corruptions
	go ck.watchMitigatedCorruptionsListXAttr(relPath)
	attrs, err := syscallcompat.Llistxattr(ck.abs(relPath))
	ck.watchDone <- struct{}{}
	if err != nil {
		fmt.Printf("fsck: error listing xattrs on %q: %v\n", relPath, err)
		ck.markCorrupt(relPath)
		return
	}
	// Try to read all xattr values
	for _, a := range attrs {
		_, err := syscallcompat.Lgetxattr(ck.abs(relPath), a)
		if err != nil {
			fmt.Printf("fsck: error reading xattr %q from %q: %v\n", a, relPath, err)
			if err == syscall.EACCES && !runsAsRoot() {
				ck.markSkipped(relPath)
			} else {
				ck.markCorrupt(relPath)
			}
		}
	}
}

// entrypoint from main()
func fsck(args *argContainer) (exitcode int) {
	if args.reverse {
		tlog.Fatal.Printf("Running -fsck with -reverse is not supported")
		os.Exit(exitcodes.Usage)
	}
	args.allow_other = false
	args.ro = true
	var err error
	args.mountpoint, err = ioutil.TempDir("", "gocryptfs.fsck.")
	if err != nil {
		tlog.Fatal.Printf("fsck: TmpDir: %v", err)
		os.Exit(exitcodes.MountPoint)
	}
	pfs, wipeKeys := initFuseFrontend(args)
	rn := pfs.(*fusefrontend.RootNode)
	rn.MitigatedCorruptions = make(chan string)
	ck := fsckObj{
		mnt:        args.mountpoint,
		rootNode:   rn,
		watchDone:  make(chan struct{}),
		seenInodes: make(map[uint64]struct{}),
	}
	if args.quiet {
		// go-fuse throws a lot of these:
		//   writer: Write/Writev failed, err: 2=no such file or directory. opcode: INTERRUPT
		// This is ugly and causes failures in xfstests. Hide them away in syslog.
		tlog.SwitchLoggerToSyslog()
	}
	// Mount
	srv := initGoFuse(pfs, args)
	// Handle SIGINT & SIGTERM
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		ck.abort = true
	}()
	defer func() {
		err = srv.Unmount()
		if err != nil {
			tlog.Warn.Printf("failed to unmount %q: %v", ck.mnt, err)
		} else {
			if err := syscall.Rmdir(ck.mnt); err != nil {
				tlog.Warn.Printf("cleaning up %q failed: %v", ck.mnt, err)
			}
		}
	}()
	// Recursively check the root dir
	ck.dir("")
	// Report results
	wipeKeys()
	if ck.abort {
		tlog.Info.Printf("fsck: aborted")
		return exitcodes.Other
	}
	if len(ck.corruptList) == 0 && len(ck.skippedList) == 0 {
		tlog.Info.Printf("fsck summary: no problems found\n")
		return 0
	}
	if len(ck.skippedList) > 0 {
		tlog.Warn.Printf("fsck: re-run this program as root to check all files!\n")
	}
	fmt.Printf("fsck summary: %d corrupt files, %d files skipped\n", len(ck.corruptList), len(ck.skippedList))
	return exitcodes.FsckErrors
}

func inum(f *os.File) uint64 {
	var st syscall.Stat_t
	err := syscall.Fstat(int(f.Fd()), &st)
	if err != nil {
		tlog.Warn.Printf("inum: fstat failed: %v", err)
		return 0
	}
	return st.Ino
}
