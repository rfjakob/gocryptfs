package fusefrontend

import (
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
)

// Container for arguments that are passed from main() to fusefrontend
type Args struct {
	Masterkey      []byte
	Cipherdir      string
	CryptoBackend  cryptocore.BackendTypeEnum
	PlaintextNames bool
	LongNames      bool
	// Should we chown a file after it has been created?
	// This only makes sense if (1) allow_other is set and (2) we run as root.
	PreserveOwner bool
}
