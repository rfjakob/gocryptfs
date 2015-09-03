// Memfs implements an in-memory file system.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"golang.org/x/net/context"

	"github.com/rfjakob/gocryptfs/frontend"
)

// debug flag enables logging of debug messages to stderr.
var debug = flag.Bool("debug", false, "enable debug log messages to stderr")

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s MOUNTPOINT\n", os.Args[0])
	flag.PrintDefaults()
}

func debugLog(msg interface{}) {
	fmt.Fprintf(os.Stderr, "%v\n", msg)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	mountpoint := flag.Arg(0)
	c, err := fuse.Mount(
		mountpoint,
		fuse.FSName("memfs"),
		fuse.Subtype("memfs"),
		fuse.LocalVolume(),
		fuse.VolumeName("Memory FS"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	cfg := &fs.Config{}
	if *debug {
		cfg.Debug = debugLog
	}

	srv := fs.New(c, cfg)
	var key [16]byte
	filesys := frontend.New(key)

	if err := srv.Serve(filesys); err != nil {
		log.Fatal(err)
	}

	// Check if the mount process has an error to report.
	<-c.Ready
	if err := c.MountError; err != nil {
		log.Fatal(err)
	}
}

type MemFS struct {
	root   *Dir
	nodeId uint64

	nodeCount uint64
	size      int64
}

// Compile-time interface checks.
var _ fs.FS = (*MemFS)(nil)
var _ fs.FSStatfser = (*MemFS)(nil)

var _ fs.Node = (*Dir)(nil)
var _ fs.NodeCreater = (*Dir)(nil)
var _ fs.NodeMkdirer = (*Dir)(nil)
var _ fs.NodeRemover = (*Dir)(nil)
var _ fs.NodeRenamer = (*Dir)(nil)
var _ fs.NodeStringLookuper = (*Dir)(nil)

var _ fs.HandleReadAller = (*File)(nil)
var _ fs.HandleWriter = (*File)(nil)
var _ fs.Node = (*File)(nil)
var _ fs.NodeOpener = (*File)(nil)
var _ fs.NodeSetattrer = (*File)(nil)

func NewMemFS() *MemFS {
	fs := &MemFS{
		nodeCount: 1,
	}
	fs.root = fs.newDir(os.ModeDir | 0777)
	if fs.root.attr.Inode != 1 {
		panic("Root node should have been assigned id 1")
	}
	return fs
}

func (m *MemFS) nextId() uint64 {
	return atomic.AddUint64(&m.nodeId, 1)
}

func (m *MemFS) newDir(mode os.FileMode) *Dir {
	n := time.Now()
	return &Dir{
		attr: fuse.Attr{
			Inode:  m.nextId(),
			Atime:  n,
			Mtime:  n,
			Ctime:  n,
			Crtime: n,
			Mode:   os.ModeDir | mode,
		},
		fs:    m,
		nodes: make(map[string]fs.Node),
	}
}

func (m *MemFS) newFile(mode os.FileMode) *File {
	n := time.Now()
	return &File{
		attr: fuse.Attr{
			Inode:  m.nextId(),
			Atime:  n,
			Mtime:  n,
			Ctime:  n,
			Crtime: n,
			Mode:   mode,
		},
		data: make([]byte, 0),
	}
}

type Dir struct {
	sync.RWMutex
	attr fuse.Attr

	fs     *MemFS
	parent *Dir
	nodes  map[string]fs.Node
}

type File struct {
	sync.RWMutex
	attr fuse.Attr

	fs   *MemFS
	data []byte
}

func (f *MemFS) Root() (fs.Node, error) {
	return f.root, nil
}

func (f *MemFS) Statfs(ctx context.Context, req *fuse.StatfsRequest,
	resp *fuse.StatfsResponse) error {
	resp.Blocks = uint64((atomic.LoadInt64(&f.size) + 511) / 512)
	resp.Bsize = 512
	resp.Files = atomic.LoadUint64(&f.nodeCount)
	return nil
}

func (f *File) Attr(ctx context.Context, o *fuse.Attr) error {
	f.RLock()
	*o = f.attr
	f.RUnlock()
	return nil
}

func (d *Dir) Attr(ctx context.Context, o *fuse.Attr) error {
	d.RLock()
	*o = d.attr
	d.RUnlock()
	return nil
}

func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	d.RLock()
	n, exist := d.nodes[name]
	d.RUnlock()

	if !exist {
		return nil, fuse.ENOENT
	}
	return n, nil
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	d.RLock()
	dirs := make([]fuse.Dirent, len(d.nodes)+2)

	// Add special references.
	dirs[0] = fuse.Dirent{
		Name:  ".",
		Inode: d.attr.Inode,
		Type:  fuse.DT_Dir,
	}
	dirs[1] = fuse.Dirent{
		Name: "..",
		Type: fuse.DT_Dir,
	}
	if d.parent != nil {
		dirs[1].Inode = d.parent.attr.Inode
	} else {
		dirs[1].Inode = d.attr.Inode
	}

	// Add remaining files.
	idx := 2
	for name, node := range d.nodes {
		ent := fuse.Dirent{
			Name: name,
		}
		switch n := node.(type) {
		case *File:
			ent.Inode = n.attr.Inode
			ent.Type = fuse.DT_File
		case *Dir:
			ent.Inode = n.attr.Inode
			ent.Type = fuse.DT_Dir
		}
		dirs[idx] = ent
		idx++
	}
	d.RUnlock()
	return dirs, nil
}

func (d *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fs.Node, error) {
	d.Lock()
	defer d.Unlock()

	if _, exists := d.nodes[req.Name]; exists {
		return nil, fuse.EEXIST
	}

	n := d.fs.newDir(req.Mode)
	d.nodes[req.Name] = n
	atomic.AddUint64(&d.fs.nodeCount, 1)

	return n, nil
}

func (d *Dir) Create(ctx context.Context, req *fuse.CreateRequest,
	resp *fuse.CreateResponse) (fs.Node, fs.Handle, error) {
	d.Lock()
	defer d.Unlock()

	if _, exists := d.nodes[req.Name]; exists {
		return nil, nil, fuse.EEXIST
	}

	n := d.fs.newFile(req.Mode)
	n.fs = d.fs
	d.nodes[req.Name] = n
	atomic.AddUint64(&d.fs.nodeCount, 1)

	resp.Attr = n.attr

	return n, n, nil
}

func (d *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fs.Node) error {
	nd := newDir.(*Dir)
	if d.attr.Inode == nd.attr.Inode {
		d.Lock()
		defer d.Unlock()
	} else if d.attr.Inode < nd.attr.Inode {
		d.Lock()
		defer d.Unlock()
		nd.Lock()
		defer nd.Unlock()
	} else {
		nd.Lock()
		defer nd.Unlock()
		d.Lock()
		defer d.Unlock()
	}

	if _, exists := d.nodes[req.OldName]; !exists {
		return fuse.ENOENT
	}

	// Rename can be used as an atomic replace, override an existing file.
	if old, exists := nd.nodes[req.NewName]; exists {
		atomic.AddUint64(&d.fs.nodeCount, ^uint64(0)) // decrement by one
		if oldFile, ok := old.(*File); !ok {
			atomic.AddInt64(&d.fs.size, -int64(oldFile.attr.Size))
		}
	}

	nd.nodes[req.NewName] = d.nodes[req.OldName]
	delete(d.nodes, req.OldName)
	return nil
}

func (d *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	d.Lock()
	defer d.Unlock()

	if n, exists := d.nodes[req.Name]; !exists {
		return fuse.ENOENT
	} else if req.Dir && len(n.(*Dir).nodes) > 0 {
		return fuse.ENOTEMPTY
	}

	delete(d.nodes, req.Name)
	atomic.AddUint64(&d.fs.nodeCount, ^uint64(0)) // decrement by one
	return nil
}

func (f *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fs.Handle,
	error) {
	return f, nil
}

func (f *File) ReadAll(ctx context.Context) ([]byte, error) {
	f.RLock()
	out := make([]byte, len(f.data))
	copy(out, f.data)
	f.RUnlock()

	return out, nil
}

func (f *File) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	f.Lock()

	l := len(req.Data)
	end := int(req.Offset) + l
	if end > len(f.data) {
		delta := end - len(f.data)
		f.data = append(f.data, make([]byte, delta)...)
		f.attr.Size = uint64(len(f.data))
		atomic.AddInt64(&f.fs.size, int64(delta))
	}
	copy(f.data[req.Offset:end], req.Data)
	resp.Size = l

	f.Unlock()
	return nil
}

func (f *File) Setattr(ctx context.Context, req *fuse.SetattrRequest,
	resp *fuse.SetattrResponse) error {
	f.Lock()

	if req.Valid.Size() {
		delta := int(req.Size) - len(f.data)
		if delta > 0 {
			f.data = append(f.data, make([]byte, delta)...)
		} else {
			f.data = f.data[0:req.Size]
		}
		f.attr.Size = req.Size
		atomic.AddInt64(&f.fs.size, int64(delta))
	}

	if req.Valid.Mode() {
		f.attr.Mode = req.Mode
	}

	if req.Valid.Atime() {
		f.attr.Atime = req.Atime
	}

	if req.Valid.AtimeNow() {
		f.attr.Atime = time.Now()
	}

	if req.Valid.Mtime() {
		f.attr.Mtime = req.Mtime
	}

	if req.Valid.MtimeNow() {
		f.attr.Mtime = time.Now()
	}

	resp.Attr = f.attr

	f.Unlock()
	return nil
}
