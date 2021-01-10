package nametransform

const (
	// Permissions for gocryptfs.diriv files
	//
	// It makes sense to have the diriv files group-readable so the FS can
	// be mounted from several users from a network drive (see
	// https://github.com/rfjakob/gocryptfs/issues/387 ).
	//
	// Note that gocryptfs.conf is still created with 0400 permissions so the
	// owner must explicitly chmod it to permit access.
	dirivPerms = 0440

	// Permissions for gocryptfs.longname.[sha256].name files
	namePerms = 0400
)
