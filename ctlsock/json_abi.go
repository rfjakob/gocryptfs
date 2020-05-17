package ctlsock

// RequestStruct is sent by a client (encoded as JSON).
// You cannot perform both encryption and decryption in the same request.
type RequestStruct struct {
	// EncryptPath is the path that should be encrypted.
	EncryptPath string
	// DecryptPath is the path that should be decrypted.
	DecryptPath string
}

// ResponseStruct is sent by the server in response to a request
// (encoded as JSON).
type ResponseStruct struct {
	// Result is the resulting decrypted or encrypted path. Empty on error.
	Result string
	// ErrNo is the error number as defined in errno.h.
	// 0 means success and -1 means that the error number is not known
	// (look at ErrText in this case).
	ErrNo int32
	// ErrText is a detailed error message.
	ErrText string
	// WarnText contains warnings that may have been encountered while
	// processing the message.
	WarnText string
}
