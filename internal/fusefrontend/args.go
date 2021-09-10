package fusefrontend

import (
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Args is a container for arguments that are passed from main() to fusefrontend
type Args struct {
	// Cipherdir is the backing storage directory (absolute path).
	// For reverse mode, Cipherdir actually contains *plaintext* files.
	Cipherdir      string
	PlaintextNames bool
	LongNames      bool
	// Should we chown a file after it has been created?
	// This only makes sense if (1) allow_other is set and (2) we run as root.
	PreserveOwner bool
	// Should we force ownership to be presented with a given user and group?
	// This only makes sense if allow_other is set. In *most* cases, it also
	// only makes sense with PreserveOwner set, but can also make sense without
	// PreserveOwner if the underlying filesystem acting as backing store
	// enforces ownership itself.
	ForceOwner *fuse.Owner
	// ConfigCustom is true when the user select a non-default config file
	// location. If it is false, reverse mode maps ".gocryptfs.reverse.conf"
	// to "gocryptfs.conf" in the plaintext dir.
	ConfigCustom bool
	// NoPrealloc disables automatic preallocation before writing
	NoPrealloc bool
	// Exclude is a list of paths to make inaccessible, starting match at
	// the filesystem root
	Exclude []string
	// ExcludeWildcards is a list of paths to make inaccessible, matched
	// anywhere, and supporting wildcards
	ExcludeWildcard []string
	// ExcludeFrom is a list of files from which to read exclusion patterns
	// (with wildcard syntax)
	ExcludeFrom []string
	// Suid is true if the filesystem has been mounted with the "-suid" flag.
	// If it is false, we can ignore the GETXATTR "security.capability" calls,
	// which are a performance problem for writes. See
	// https://github.com/rfjakob/gocryptfs/issues/515 for details.
	Suid bool
	// Enable the FUSE kernel_cache option
	KernelCache bool
	// SharedStorage disables caching & hard link tracking,
	// enabled via cli flag "-sharedstorage"
	SharedStorage bool
	// OneFileSystem disables crossing filesystem boundaries,
	// like rsync's `--one-file-system` does.
	// Only applicable to reverse mode.
	OneFileSystem bool
	// DeterministicNames disables gocryptfs.diriv files
	DeterministicNames bool
}
