package fusefrontend

import (
	"github.com/hanwen/go-fuse/v2/fs"
)

// Check that we have implemented the fs.Node* interfaces
var _ = (fs.NodeGetattrer)((*Node)(nil))
var _ = (fs.NodeLookuper)((*Node)(nil))
var _ = (fs.NodeReaddirer)((*Node)(nil))
var _ = (fs.NodeCreater)((*Node)(nil))
var _ = (fs.NodeMkdirer)((*Node)(nil))
var _ = (fs.NodeRmdirer)((*Node)(nil))
var _ = (fs.NodeUnlinker)((*Node)(nil))
var _ = (fs.NodeReadlinker)((*Node)(nil))
var _ = (fs.NodeOpener)((*Node)(nil))
var _ = (fs.NodeOpendirer)((*Node)(nil))
var _ = (fs.NodeSetattrer)((*Node)(nil))
var _ = (fs.NodeStatfser)((*Node)(nil))
var _ = (fs.NodeMknoder)((*Node)(nil))
var _ = (fs.NodeLinker)((*Node)(nil))
var _ = (fs.NodeSymlinker)((*Node)(nil))
var _ = (fs.NodeRenamer)((*Node)(nil))
var _ = (fs.NodeGetxattrer)((*Node)(nil))
var _ = (fs.NodeSetxattrer)((*Node)(nil))
var _ = (fs.NodeRemovexattrer)((*Node)(nil))
var _ = (fs.NodeListxattrer)((*Node)(nil))

/* TODO
var _ = (fs.NodeCopyFileRanger)((*Node)(nil))
*/
