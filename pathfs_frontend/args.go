package pathfs_frontend

// Container for arguments that are passed from main() to pathfs_frontend
type Args struct {
	Masterkey      []byte
	Cipherdir      string
	OpenSSL        bool
	PlaintextNames bool
	DirIV          bool
}
