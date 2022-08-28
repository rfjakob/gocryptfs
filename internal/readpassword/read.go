// Package readpassword reads a password from the terminal of from stdin.
package readpassword

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// 2kB limit like EncFS
	maxPasswordLen = 2048
)

// Once tries to get a password from the user, either from the terminal, extpass, passfile
// or stdin. Leave "prompt" empty to use the default "Password: " prompt.
func Once(extpass []string, passfile []string, prompt string) ([]byte, error) {
	if len(passfile) != 0 {
		return readPassFileConcatenate(passfile)
	}
	if len(extpass) != 0 {
		return readPasswordExtpass(extpass)
	}
	if prompt == "" {
		prompt = "Password"
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return readPasswordStdin(prompt)
	}
	return readPasswordTerminal(prompt + ": ")
}

// Twice is the same as Once but will prompt twice if we get the password from
// the terminal.
func Twice(extpass []string, passfile []string) ([]byte, error) {
	if len(passfile) != 0 {
		return readPassFileConcatenate(passfile)
	}
	if len(extpass) != 0 {
		return readPasswordExtpass(extpass)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return readPasswordStdin("Password")
	}
	p1, err := readPasswordTerminal("Password: ")
	if err != nil {
		return nil, err
	}
	p2, err := readPasswordTerminal("Repeat: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p1, p2) {
		return nil, fmt.Errorf("Passwords do not match")
	}
	// Wipe the password duplicate from memory
	for i := range p2 {
		p2[i] = 0
	}
	return p1, nil
}

// readPasswordTerminal reads a line from the terminal.
// Exits on read error or empty result.
func readPasswordTerminal(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprintf(os.Stderr, prompt)
	// term.ReadPassword removes the trailing newline
	p, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("Could not read password from terminal: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "\n")
	if len(p) == 0 {
		return nil, fmt.Errorf("Password is empty")
	}
	return p, nil
}

// readPasswordStdin reads a line from stdin.
// It exits with a fatal error on read error or empty result.
func readPasswordStdin(prompt string) ([]byte, error) {
	tlog.Info.Printf("Reading %s from stdin", prompt)
	p, err := readLineUnbuffered(os.Stdin)
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("Got empty %s from stdin", prompt)
	}
	return p, nil
}

// readPasswordExtpass executes the "extpass" program and returns the first line
// of the output.
// Exits on read error or empty result.
func readPasswordExtpass(extpass []string) ([]byte, error) {
	var parts []string
	if len(extpass) == 1 {
		parts = strings.Split(extpass[0], " ")
	} else {
		parts = extpass
	}
	tlog.Info.Printf("Reading password from extpass program %q, arguments: %q\n", parts[0], parts[1:])
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("extpass pipe setup failed: %v", err)
	}
	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("extpass cmd start failed: %v", err)
	}
	p, err := readLineUnbuffered(pipe)
	if err != nil {
		return nil, err
	}
	pipe.Close()
	err = cmd.Wait()
	if err != nil {
		return nil, fmt.Errorf("extpass program returned an error: %v", err)
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("extpass: password is empty")
	}
	return p, nil
}

// readLineUnbuffered reads single bytes from "r" util it gets "\n" or EOF.
// The returned string does NOT contain the trailing "\n".
func readLineUnbuffered(r io.Reader) (l []byte, err error) {
	b := make([]byte, 1)
	for {
		if len(l) > maxPasswordLen {
			return nil, fmt.Errorf("fatal: maximum password length of %d bytes exceeded", maxPasswordLen)
		}
		n, err := r.Read(b)
		if err == io.EOF {
			return l, nil
		}
		if err != nil {
			return nil, fmt.Errorf("readLineUnbuffered: %v", err)
		}
		if n == 0 {
			continue
		}
		if b[0] == '\n' {
			return l, nil
		}
		l = append(l, b...)
	}
}
