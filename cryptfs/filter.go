package cryptfs

// IsFiltered - check if "path" should be forbidden
//
// Used to prevent name clashes with gocryptfs.conf
// when file names are not encrypted
func (be *CryptFS) IsFiltered(path string) bool {
	// gocryptfs.conf in the root directory is forbidden
	if be.plaintextNames == true && path == "gocryptfs.conf" {
		Warn.Printf("The name \"/gocryptfs.conf\" is reserved when \"--plaintextnames\" is used\n")
		return true
	}
	return false
}
