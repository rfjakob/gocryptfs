package nametransform

const (
	// Permissions for gocryptfs.diriv files.
	// The gocryptfs.diriv files are created once, never modified,
	// never chmod'ed or chown'ed.
	//
	// Group-readable so the FS can be mounted by several users in the same group
	// (see https://github.com/rfjakob/gocryptfs/issues/387 ).
	//
	// Note that gocryptfs.conf is still created with 0400 permissions so the
	// owner must explicitly chmod it to permit access.
	//
	// World-readable so an encrypted directory can be copied by the non-root
	// owner when gocryptfs is running as root
	// ( https://github.com/rfjakob/gocryptfs/issues/539 ).
	dirivPerms = 0444

	// Permissions for gocryptfs.longname.[sha256].name files.
	// The .name files are created once, never modified,
	// never chmod'ed or chown'ed.
	//
	// Group- and world-readable for the same reasons as the gocryptfs.diriv
	// files (see above).
	namePerms = 0444
)
