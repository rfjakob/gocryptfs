package cryptfs

// IsFiltered - check if "path" should be forbidden
//
// Used to prevent name clashes with gocryptfs.conf
// when file names are not encrypted
func (be *CryptFS) IsFiltered(path string) bool {
	// gocryptfs.conf in the root directory is forbidden
	if be.plaintextNames == true && path == ConfDefaultName {
		Warn.Printf("The name /%s is reserved when -plaintextnames is used\n",
			ConfDefaultName)
		return true
	}
	return false
}
