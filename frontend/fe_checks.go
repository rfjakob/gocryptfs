package frontend

import (
	"bazil.org/fuse/fs"
)

// Compile-time interface checks.
var _ fs.FS = (*FS)(nil)
var _ fs.FSStatfser = (*FS)(nil)

var _ fs.Node = (*Dir)(nil)
var _ fs.NodeCreater = (*Dir)(nil)
var _ fs.NodeMkdirer = (*Dir)(nil)
var _ fs.NodeRemover = (*Dir)(nil)
var _ fs.NodeRenamer = (*Dir)(nil)
var _ fs.HandleReadDirAller = (*Dir)(nil)

var _ fs.HandleReader = (*File)(nil)
var _ fs.HandleWriter = (*File)(nil)
var _ fs.Node = (*File)(nil)
var _ fs.NodeOpener = (*File)(nil)
var _ fs.NodeSetattrer = (*File)(nil)

func foo(h fs.HandleReadDirAller) {

}

func init() {
	var d Dir
	foo(&d)
}
