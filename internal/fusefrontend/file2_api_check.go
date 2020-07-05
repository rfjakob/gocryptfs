package fusefrontend

import (
	"github.com/hanwen/go-fuse/v2/fs"
)

// Check that we have implemented the fs.File* interfaces
var _ = (fs.FileGetattrer)((*File2)(nil))
var _ = (fs.FileSetattrer)((*File2)(nil))

/* TODO
var _ = (fs.FileHandle)((*File2)(nil))
var _ = (fs.FileReleaser)((*File2)(nil))
var _ = (fs.FileReader)((*File2)(nil))
var _ = (fs.FileWriter)((*File2)(nil))
var _ = (fs.FileGetlker)((*File2)(nil))
var _ = (fs.FileSetlker)((*File2)(nil))
var _ = (fs.FileSetlkwer)((*File2)(nil))
var _ = (fs.FileLseeker)((*File2)(nil))
var _ = (fs.FileFlusher)((*File2)(nil))
var _ = (fs.FileFsyncer)((*File2)(nil))
var _ = (fs.FileAllocater)((*File2)(nil))
*/
