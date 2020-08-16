package fusefrontend_reverse

import (
	"github.com/hanwen/go-fuse/v2/fs"
)

// Check that we have implemented the fs.File* interfaces
var _ = (fs.FileReader)((*File)(nil))
var _ = (fs.FileReleaser)((*File)(nil))
var _ = (fs.FileLseeker)((*File)(nil))

/* Not needed
var _ = (fs.FileGetattrer)((*File)(nil))
var _ = (fs.FileGetlker)((*File)(nil))
var _ = (fs.FileSetlker)((*File)(nil))
var _ = (fs.FileSetlkwer)((*File)(nil))
*/

/* Will not implement these - reverse mode is read-only!
var _ = (fs.FileSetattrer)((*File)(nil))
var _ = (fs.FileWriter)((*File)(nil))
var _ = (fs.FileFsyncer)((*File)(nil))
var _ = (fs.FileFlusher)((*File)(nil))
var _ = (fs.FileAllocater)((*File)(nil))
*/
