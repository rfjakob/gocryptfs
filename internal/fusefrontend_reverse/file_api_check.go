package fusefrontend_reverse

import (
	"github.com/hanwen/go-fuse/v2/fs"
)

// Check that we have implemented the fs.File* interfaces
var _ = (fs.FileReader)((*File)(nil))
var _ = (fs.FileReleaser)((*File)(nil))

/* TODO
var _ = (fs.FileLseeker)((*File2)(nil))
*/

/* Not needed
var _ = (fs.FileGetattrer)((*File2)(nil))
var _ = (fs.FileGetlker)((*File2)(nil))
var _ = (fs.FileSetlker)((*File2)(nil))
var _ = (fs.FileSetlkwer)((*File2)(nil))
*/

/* Will not implement these - reverse mode is read-only!
var _ = (fs.FileSetattrer)((*File2)(nil))
var _ = (fs.FileWriter)((*File2)(nil))
var _ = (fs.FileFsyncer)((*File2)(nil))
var _ = (fs.FileFlusher)((*File2)(nil))
var _ = (fs.FileAllocater)((*File2)(nil))
*/
