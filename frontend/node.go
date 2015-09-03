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

func StatToAttr(s *syscall.Stat_t, a *fuse.Attr) {
	a.Inode = s.Ino
	a.Size = uint64(s.Size)
	a.Blocks = uint64(s.Blocks)
	a.Atime = time.Unix(s.Atim.Sec, s.Atim.Nsec)
	a.Mtime = time.Unix(s.Mtim.Sec, s.Mtim.Nsec)
	a.Ctime = time.Unix(s.Ctim.Sec, s.Ctim.Nsec)
	a.Mode = os.FileMode(s.Mode) | os.ModeDir
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
