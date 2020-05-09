// Package ctlsock is a Go library that can be used to query the
// gocryptfs control socket interface. This interface can be
// activated by passing `-ctlsock /tmp/my.sock` to gocryptfs on the
// command line.
package ctlsock

// RequestStruct is sent by a client
type RequestStruct struct {
	EncryptPath string
	DecryptPath string
}

// ResponseStruct is sent by the server in response to a request
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
