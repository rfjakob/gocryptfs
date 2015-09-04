package frontend

import (
	"github.com/rfjakob/gocryptfs/cryptfs"
	"github.com/rfjakob/cluefs/lib/cluefs"
)

type File struct {
	*cryptfs.CryptFile
	*cluefs.File
}
