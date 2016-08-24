package fusefrontend_reverse

import (
	"os"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
)

type file struct {
	fd *os.File
	// Content encryption helper
	contentEnc *contentenc.ContentEnc

	// nodefs.defaultFile returns ENOSYS for all operations
	nodefs.File
}

func NewFile(fd *os.File, contentEnc *contentenc.ContentEnc) (nodefs.File, fuse.Status) {
	return &file{
		fd:         fd,
		contentEnc: contentEnc,
		File:       nodefs.NewDefaultFile(),
	}, fuse.OK
}
