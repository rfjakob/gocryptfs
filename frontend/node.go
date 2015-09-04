package frontend

import (
	"fmt"
	"os"
	"time"
	"syscall"
	"io/ioutil"
	"path"

	"golang.org/x/net/context"

	//"github.com/rfjakob/gocryptfs/cryptfs"
	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)


type Node struct {
	fs.NodeRef
	backing string
	parentFS *FS
}

// FileModeFromStat - create os.FileMode from stat value
// For some reason, they use different constants.
// Adapted from https://golang.org/src/os/stat_linux.go
func FileModeFromStat(st *syscall.Stat_t) os.FileMode {
	fileMode := os.FileMode(st.Mode & 0777)
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFBLK:
		fileMode |= os.ModeDevice
	case syscall.S_IFCHR:
		fileMode |= os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFDIR:
		fileMode |= os.ModeDir
	case syscall.S_IFIFO:
		fileMode |= os.ModeNamedPipe
	case syscall.S_IFLNK:
		fileMode |= os.ModeSymlink
	case syscall.S_IFREG:
		// nothing to do
	case syscall.S_IFSOCK:
		fileMode |= os.ModeSocket
	}
	if st.Mode & syscall.S_ISGID != 0 {
		fileMode |= os.ModeSetgid
	}
	if st.Mode & syscall.S_ISUID != 0 {
		fileMode |= os.ModeSetuid
	}
	if st.Mode & syscall.S_ISVTX != 0 {
		fileMode |= os.ModeSticky
	}
	return fileMode
}


func StatToAttr(s *syscall.Stat_t, a *fuse.Attr) {
	a.Inode = s.Ino
	a.Size = uint64(s.Size)
	a.Blocks = uint64(s.Blocks)
	a.Atime = time.Unix(s.Atim.Sec, s.Atim.Nsec)
	a.Mtime = time.Unix(s.Mtim.Sec, s.Mtim.Nsec)
	a.Ctime = time.Unix(s.Ctim.Sec, s.Ctim.Nsec)
	a.Mode = FileModeFromStat(s)
	a.Nlink = uint32(s.Nlink)
	a.Uid = uint32(s.Uid)
	a.Gid = uint32(s.Gid)
	a.Rdev = uint32(s.Rdev)
}

func (n Node) Attr(ctx context.Context, attr *fuse.Attr) error {
	var err error
	var st syscall.Stat_t
	if n.backing == "" {
		// When GetAttr is called for the toplevel directory, we always want
		// to look through symlinks.
		fmt.Printf("Attr %s\n", n.parentFS.backing)
		//err = syscall.Stat(n.parentFS.backing, &st)
		err = syscall.Stat("/", &st)
	} else {
		fmt.Printf("Attr %s\n", path.Join(n.parentFS.backing, n.backing))
		p := path.Join(n.parentFS.backing, n.backing)
		err = syscall.Lstat(p, &st)
	}
	if err != nil {
		return err
	}
	StatToAttr(&st, attr)
	return nil
}

func (n *Node) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	entries, err := ioutil.ReadDir(n.backing)
	if err != nil {
		return nil, err
	}
	var fuseEntries []fuse.Dirent
	for _, e := range entries {
		var d fuse.Dirent
		d.Name = e.Name()
		fuseEntries = append(fuseEntries, d)
	}
	return fuseEntries, err
}

func (n *Node) Lookup(ctx context.Context, name string) (fs.Node, error) {
	if name == "hello" {
		return Node{}, nil
	}
	return nil, fuse.ENOENT
}
