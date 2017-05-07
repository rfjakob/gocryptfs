// Package exitcodes contains all well-defined exit codes that gocryptfs
// can return.
package exitcodes

import (
	"fmt"
	"os"
)

const (
	// Usage error: cli syntax etc
	Usage = 1
	// 2 is reserved because it is used by Go panic

	// Mount is an error on mount
	Mount = 3
	// CipherDir means that the CIPHERDIR does not exist
	CipherDir = 6
	// Init is an error on filesystem init
	Init = 7
	// LoadConf is an error while loading gocryptfs.conf
	LoadConf = 8
	// ReadPassword means something went wrong reading the password
	ReadPassword = 9
	// MountPoint error means that the mountpoint is invalid (not empty etc).
	MountPoint = 10
	// Other error - please inspect the message
	Other = 11
	// PasswordIncorrect - the password was incorrect
	PasswordIncorrect = 12
	// ScryptParams means that scrypt was called with invalid parameters
	ScryptParams = 13
	// MasterKey means that something went wrong when parsing the "-masterkey"
	// command line option
	MasterKey = 14
	// SigInt means we got SIGINT
	SigInt = 15
	// PanicLog means the panic log was not empty when we were unmounted
	PanicLog = 16
	// ForkChild means forking the worker child failed
	ForkChild = 17
	// OpenSSL means you tried to enable OpenSSL, but we were compiled without it.
	OpenSSL = 18
)

// Err wraps an error with an associated numeric exit code
type Err struct {
	error
	code int
}

// NewErr returns an error containing "msg" and the exit code "code".
func NewErr(msg string, code int) Err {
	return Err{
		error: fmt.Errorf(msg),
		code:  code,
	}
}

// Exit extracts the numeric exit code from "err" (if available) and exits the
// application.
func Exit(err error) {
	err2, ok := err.(Err)
	if !ok {
		os.Exit(Other)
	}
	os.Exit(err2.code)
}
