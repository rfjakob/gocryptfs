package fusefrontend

import (
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
)

// Args is a container for arguments that are passed from main() to fusefrontend
type Args struct {
	Masterkey      []byte
	Cipherdir      string
	CryptoBackend  cryptocore.BackendTypeEnum
	PlaintextNames bool
	LongNames      bool
	// Should we chown a file after it has been created?
	// This only makes sense if (1) allow_other is set and (2) we run as root.
	PreserveOwner bool
	// ConfigCustom is true when the user select a non-default config file
	// location. If it is false, reverse mode maps ".gocryptfs.reverse.conf"
	// to "gocryptfs.conf" in the plaintext dir.
	ConfigCustom bool
	// Raw64 is true when RawURLEncoding (without padding) should be used for
	// file names
	Raw64 bool
	// NoPrealloc disables automatic preallocation before writing
	NoPrealloc bool
}
