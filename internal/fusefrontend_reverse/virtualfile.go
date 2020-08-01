package fusefrontend_reverse

import (
	"syscall"
)

const (
	// virtualFileMode is the mode to use for virtual files (gocryptfs.diriv and
	// *.name). They are always readable, as stated in func Access
	virtualFileMode = syscall.S_IFREG | 0444
	// We use inomap's `Tag` feature to generate unique inode numbers for
	// virtual files. These are the tags we use.
	inoTagDirIV    = 1
	inoTagNameFile = 2
)
