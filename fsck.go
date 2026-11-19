package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// fsckObj walks the filesystem by calling the fusefrontend node operations
// directly, without mounting it via FUSE.
type fsckObj struct {
	rootNode *fusefrontend.RootNode
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

// markError marks relPath as skipped if err is a permission error and we
// are not root, and as corrupt otherwise.
func (ck *fsckObj) markError(relPath string, err error) {
	if errors.Is(err, os.ErrPermission) && !runsAsRoot() {
		ck.markSkipped(relPath)
	} else {
		ck.markCorrupt(relPath)
	}
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
func (ck *fsckObj) dir(inode *fs.Inode, relPath string) {
	tlog.Debug.Printf("ck.dir %q\n", relPath)
	ck.xattrs(inode, relPath)
	// Run OpendirHandle and Readdirent and catch transparently mitigated corruptions
	go ck.watchMitigatedCorruptionsOpenDir(relPath)
	entries, errno := ck.readdir(inode, relPath)
	ck.watchDone <- struct{}{}
	if errno != 0 {
		ck.markError(relPath, errno)
		return
	}
	// Sort alphabetically to make fsck runs deterministic
	sort.Strings(entries)
	for _, entry := range entries {
		if ck.abort {
			return
		}
		nextPath := filepath.Join(relPath, entry)
		var out fuse.EntryOut
		child, errno := inode.Operations().(fs.NodeLookuper).Lookup(context.Background(), entry, &out)
		if errno != 0 {
			fmt.Printf("fsck: error looking up %q: %v\n", nextPath, errno)
			ck.markError(nextPath, errno)
			continue
		}
		// Node operations find the backing file via the path from the root,
		// so the child must be part of the tree.
		inode.AddChild(entry, child, true)
		filetype := out.Attr.Mode & syscall.S_IFMT
		switch filetype {
		case syscall.S_IFDIR:
			ck.dir(child, nextPath)
		case syscall.S_IFREG:
			ck.file(child, nextPath, &out.Attr)
		case syscall.S_IFLNK:
			ck.symlink(child, nextPath)
		case syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFBLK, syscall.S_IFCHR:
			// nothing to check
		default:
			fmt.Printf("fsck: unhandled file type %x\n", filetype)
		}
		// Drop the child (and its subtree) again so memory usage does not grow
		// with the size of the filesystem.
		inode.RmChild(entry)
	}
}

// readdir returns the names of all entries in the directory, without "." and "..".
func (ck *fsckObj) readdir(inode *fs.Inode, relPath string) (entries []string, errno syscall.Errno) {
	fh, _, errno := inode.Operations().(fs.NodeOpendirHandler).OpendirHandle(context.Background(), syscall.O_RDONLY)
	if errno != 0 {
		fmt.Printf("fsck: error opening dir %q: %v\n", relPath, errno)
		return nil, errno
	}
	defer fh.(fs.FileReleasedirer).Releasedir(context.Background(), 0)
	for {
		entry, errno := fh.(fs.FileReaddirenter).Readdirent(context.Background())
		if errno != 0 {
			fmt.Printf("fsck: error reading dir %q: %v\n", relPath, errno)
			return nil, errno
		}
		if entry == nil {
			return entries, 0
		}
		if entry.Name == "." || entry.Name == ".." {
			continue
		}
		entries = append(entries, entry.Name)
	}
}

func (ck *fsckObj) symlink(inode *fs.Inode, relPath string) {
	_, errno := inode.Operations().(fs.NodeReadlinker).Readlink(context.Background())
	if errno != 0 {
		ck.markCorrupt(relPath)
		fmt.Printf("fsck: error reading symlink %q: %v\n", relPath, errno)
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
func (ck *fsckObj) file(inode *fs.Inode, relPath string, attr *fuse.Attr) {
	tlog.Debug.Printf("ck.file %q\n", relPath)
	if attr.Nlink > 1 {
		// Due to hard links, we may have already checked this file.
		if _, ok := ck.seenInodes[attr.Ino]; ok {
			tlog.Debug.Printf("ck.file : skipping %q (inode number %d already seen)\n", relPath, attr.Ino)
			return
		}
		ck.seenInodes[attr.Ino] = struct{}{}
	}
	ck.xattrs(inode, relPath)
	fh, _, errno := inode.Operations().(fs.NodeOpener).Open(context.Background(), syscall.O_RDONLY)
	if errno != 0 {
		fmt.Printf("fsck: error opening file %q: %v\n", relPath, errno)
		ck.markError(relPath, errno)
		return
	}
	defer fh.(fs.FileReleaser).Release(context.Background())
	reader := fh.(fs.FileReader)
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
		res, errno := reader.Read(context.Background(), buf, off)
		if errno != 0 {
			ck.markCorrupt(relPath)
			fmt.Printf("fsck: error reading file %q (inum %d): %v\n", relPath, attr.Ino, errno)
			return
		}
		data, status := res.Bytes(buf)
		if !status.Ok() {
			ck.markCorrupt(relPath)
			fmt.Printf("fsck: error reading file %q (inum %d): %v\n", relPath, attr.Ino, status)
			return
		}
		// Short read means EOF
		if len(data) < len(buf) {
			return
		}
		off += int64(len(data))
		// If we seem to be in the middle of a file hole, try to skip to the next
		// data section.
		if bytes.Equal(data, allZero) {
			tlog.Debug.Printf("ck.file: trying to skip file hole\n")
			const SEEK_DATA = 3
			nextOff, errno := fh.(fs.FileLseeker).Lseek(context.Background(), uint64(off), SEEK_DATA)
			if errno == syscall.ENXIO {
				// No more data after `off`
				return
			}
			if errno == 0 {
				off = int64(nextOff)
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

// Check xattrs on file/dir
func (ck *fsckObj) xattrs(inode *fs.Inode, relPath string) {
	ops := inode.Operations()
	// Run Listxattr() and catch transparently mitigated corruptions
	go ck.watchMitigatedCorruptionsListXAttr(relPath)
	list, errno := getBuf(func(dest []byte) (uint32, syscall.Errno) {
		return ops.(fs.NodeListxattrer).Listxattr(context.Background(), dest)
	})
	ck.watchDone <- struct{}{}
	if errno != 0 {
		fmt.Printf("fsck: error listing xattrs on %q: %v\n", relPath, errno)
		ck.markCorrupt(relPath)
		return
	}
	// Try to read all xattr values
	for _, a := range bytes.Split(list, []byte{0}) {
		if len(a) == 0 {
			continue
		}
		_, errno := getBuf(func(dest []byte) (uint32, syscall.Errno) {
			return ops.(fs.NodeGetxattrer).Getxattr(context.Background(), string(a), dest)
		})
		if errno != 0 {
			fmt.Printf("fsck: error reading xattr %q from %q: %v\n", a, relPath, errno)
			ck.markError(relPath, errno)
		}
	}
}

// getBuf calls `f` with a growing buffer until it does not return ERANGE.
// Used for Listxattr and Getxattr.
func getBuf(f func(dest []byte) (uint32, syscall.Errno)) ([]byte, syscall.Errno) {
	buf := make([]byte, 1024)
	for {
		sz, errno := f(buf)
		if errno == syscall.ERANGE && int(sz) > len(buf) {
			buf = make([]byte, sz)
			continue
		}
		if errno != 0 {
			return nil, errno
		}
		return buf[:sz], 0
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
	pfs, wipeKeys := initFuseFrontend(args)
	rn := pfs.(*fusefrontend.RootNode)
	// We never mount the filesystem, but NewNodeFS initializes the root
	// inode, which is required for the node operations to work.
	_ = fs.NewNodeFS(rn, nil)
	rn.MitigatedCorruptions = make(chan string)
	ck := fsckObj{
		rootNode:   rn,
		watchDone:  make(chan struct{}),
		seenInodes: make(map[uint64]struct{}),
	}
	// Handle SIGINT & SIGTERM
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		ck.abort = true
	}()
	// Recursively check the root dir
	tlog.Info.Println(tlog.ColorGreen + "Checking filesystem..." + tlog.ColorReset)
	ck.dir(rn.EmbeddedInode(), "")
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
