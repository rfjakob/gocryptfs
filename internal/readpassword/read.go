// Package readpassword reads a password from the terminal of from stdin.
package readpassword

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// 2kB limit like EncFS
	maxPasswordLen = 2048
)

// Once tries to get a password from the user, either from the terminal, extpass, passfile
// or stdin. Leave "prompt" empty to use the default "Password: " prompt.
func Once(extpass []string, passfile []string, prompt string) []byte {
	if len(passfile) != 0 {
		return readPassFileConcatenate(passfile)
	}
	if len(extpass) != 0 {
		return readPasswordExtpass(extpass)
	}
	if prompt == "" {
		prompt = "Password"
	}
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return readPasswordStdin(prompt)
	}
	return readPasswordTerminal(prompt + ": ")
}

// Twice is the same as Once but will prompt twice if we get the password from
// the terminal.
func Twice(extpass []string, passfile []string) []byte {
	if len(passfile) != 0 {
		return readPassFileConcatenate(passfile)
	}
	if len(extpass) != 0 {
		return readPasswordExtpass(extpass)
	}
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return readPasswordStdin("Password")
	}
	p1 := readPasswordTerminal("Password: ")
	p2 := readPasswordTerminal("Repeat: ")
	if !bytes.Equal(p1, p2) {
		tlog.Fatal.Println("Passwords do not match")
		os.Exit(exitcodes.ReadPassword)
	}
	// Wipe the password duplicate from memory
	for i := range p2 {
		p2[i] = 0
	}
	return p1
}

// readPasswordTerminal reads a line from the terminal.
// Exits on read error or empty result.
func readPasswordTerminal(prompt string) []byte {
	fd := int(os.Stdin.Fd())
	fmt.Fprintf(os.Stderr, prompt)
	// terminal.ReadPassword removes the trailing newline
	p, err := terminal.ReadPassword(fd)
	if err != nil {
		tlog.Fatal.Printf("Could not read password from terminal: %v\n", err)
		os.Exit(exitcodes.ReadPassword)
	}
	fmt.Fprintf(os.Stderr, "\n")
	if len(p) == 0 {
		tlog.Fatal.Println("Password is empty")
		os.Exit(exitcodes.PasswordEmpty)
	}
	return p
}

// readPasswordStdin reads a line from stdin.
// It exits with a fatal error on read error or empty result.
func readPasswordStdin(prompt string) []byte {
	tlog.Info.Printf("Reading %s from stdin", prompt)
	p := readLineUnbuffered(os.Stdin)
	if len(p) == 0 {
		tlog.Fatal.Printf("Got empty %s from stdin", prompt)
		os.Exit(exitcodes.ReadPassword)
	}
	return p
}

// readPasswordExtpass executes the "extpass" program and returns the first line
// of the output.
// Exits on read error or empty result.
func readPasswordExtpass(extpass []string) []byte {
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
		tlog.Fatal.Printf("extpass pipe setup failed: %v", err)
		os.Exit(exitcodes.ReadPassword)
	}
	err = cmd.Start()
	if err != nil {
		tlog.Fatal.Printf("extpass cmd start failed: %v", err)
		os.Exit(exitcodes.ReadPassword)
	}
	p := readLineUnbuffered(pipe)
	pipe.Close()
	err = cmd.Wait()
	if err != nil {
		tlog.Fatal.Printf("extpass program returned an error: %v", err)
		os.Exit(exitcodes.ReadPassword)
	}
	if len(p) == 0 {
		tlog.Fatal.Println("extpass: password is empty")
		os.Exit(exitcodes.ReadPassword)
	}
	return p
}

// readLineUnbuffered reads single bytes from "r" util it gets "\n" or EOF.
// The returned string does NOT contain the trailing "\n".
func readLineUnbuffered(r io.Reader) (l []byte) {
	b := make([]byte, 1)
	for {
		if len(l) > maxPasswordLen {
			tlog.Fatal.Printf("fatal: maximum password length of %d bytes exceeded", maxPasswordLen)
			os.Exit(exitcodes.ReadPassword)
		}
		n, err := r.Read(b)
		if err == io.EOF {
			return l
		}
		if err != nil {
			tlog.Fatal.Printf("readLineUnbuffered: %v", err)
			os.Exit(exitcodes.ReadPassword)
		}
		if n == 0 {
			continue
		}
		if b[0] == '\n' {
			return l
		}
		l = append(l, b...)
	}
}
