package fusefrontend

import (
	"time"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/inomap"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// RootNode is the root of the filesystem tree of Nodes.
type RootNode struct {
	Node
	// args stores configuration arguments
	args Args
	// Filename encryption helper
	nameTransform nametransform.NameTransformer
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
	// MitigatedCorruptions is used to report data corruption that is internally
	// mitigated by ignoring the corrupt item. For example, when OpenDir() finds
	// a corrupt filename, we still return the other valid filenames.
	// The corruption is logged to syslog to inform the user,	and in addition,
	// the corrupt filename is logged to this channel via
	// reportMitigatedCorruption().
	// "gocryptfs -fsck" reads from the channel to also catch these transparently-
	// mitigated corruptions.
	MitigatedCorruptions chan string
	// IsIdle flag is set to zero each time fs.isFiltered() is called
	// (uint32 so that it can be reset with CompareAndSwapUint32).
	// When -idle was used when mounting, idleMonitor() sets it to 1
	// periodically.
	IsIdle uint32
	// inoMap translates inode numbers from different devices to unique inode
	// numbers.
	inoMap *inomap.InoMap
}

func NewRootNode(args Args, c *contentenc.ContentEnc, n nametransform.NameTransformer) *RootNode {
	// TODO
	return &RootNode{
		args:          args,
		nameTransform: n,
		contentEnc:    c,
		inoMap:        inomap.New(),
	}
}

// reportMitigatedCorruption is used to report a corruption that was transparently
// mitigated and did not return an error to the user. Pass the name of the corrupt
// item (filename for OpenDir(), xattr name for ListXAttr() etc).
// See the MitigatedCorruptions channel for more info.
func (rn *RootNode) reportMitigatedCorruption(item string) {
	if rn.MitigatedCorruptions == nil {
		return
	}
	select {
	case rn.MitigatedCorruptions <- item:
	case <-time.After(1 * time.Second):
		tlog.Warn.Printf("BUG: reportCorruptItem: timeout")
		//debug.PrintStack()
		return
	}
}
