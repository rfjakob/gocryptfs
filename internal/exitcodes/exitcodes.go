// Package exitcodes contains all well-defined exit codes that gocryptfs
// can return.
package exitcodes

import (
	"fmt"
	"os"
)

const (
	// Other error - please inspect the message
	Other = 11
	// PasswordIncorrect - the password was incorrect
	PasswordIncorrect = 12
	// TODO several other exit codes are defined in main.go. These will be
	// ported over here.
)

// Err wraps and error with an associated numeric exit code
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
