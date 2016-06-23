package fusefrontend

// Container for arguments that are passed from main() to fusefrontend
type Args struct {
	Masterkey      []byte
	Cipherdir      string
	OpenSSL        bool
	PlaintextNames bool
	LongNames      bool
}
