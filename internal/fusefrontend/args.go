package fusefrontend

import (
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
)

// Args is a container for arguments that are passed from main() to fusefrontend
type Args struct {
	Masterkey []byte
	// Cipherdir is the backing storage directory (absolute path).
	// For reverse mode, Cipherdir actually contains *plaintext* files.
	Cipherdir      string
	CryptoBackend  cryptocore.AEADTypeEnum
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
	// file names.
	// Corresponds to the Raw64 feature flag introduced in gocryptfs v1.2.
	Raw64 bool
	// NoPrealloc disables automatic preallocation before writing
	NoPrealloc bool
	// Use HKDF key derivation.
	// Corresponds to the HKDF feature flag introduced in gocryptfs v1.3.
	HKDF bool
	// Try to serialize read operations, "-serialize_reads"
	SerializeReads bool
	// Force decode even if integrity check fails (openSSL only)
	ForceDecode bool
}
