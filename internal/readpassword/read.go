package readpassword

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/rfjakob/gocryptfs/internal/toggledlog"
)

const (
	exitCode = 9
)

// TODO
var colorReset, colorRed string

// Once() tries to get a password from the user, either from the terminal,
// extpass or stdin.
func Once(extpass string) string {
	if extpass != "" {
		return readPasswordExtpass(extpass)
	}
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return readPasswordStdin()
	}
	return readPasswordTerminal("Password: ")
}

// Twice() is the same as Once but will prompt twice if we get
// the password from the terminal.
func Twice(extpass string) string {
	if extpass != "" {
		return readPasswordExtpass(extpass)
	}
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return readPasswordStdin()
	}
	p1 := readPasswordTerminal("Password: ")
	p2 := readPasswordTerminal("Repeat: ")
	if p1 != p2 {
		toggledlog.Fatal.Println(colorRed + "Passwords do not match" + colorReset)
		os.Exit(exitCode)
	}
	return p1
}

// readPasswordTerminal reads a line from the terminal.
// Exits on read error or empty result.
func readPasswordTerminal(prompt string) string {
	fd := int(os.Stdin.Fd())
	fmt.Fprintf(os.Stderr, prompt)
	// terminal.ReadPassword removes the trailing newline
	p, err := terminal.ReadPassword(fd)
	if err != nil {
		toggledlog.Fatal.Printf(colorRed+"Could not read password from terminal: %v\n"+colorReset, err)
		os.Exit(exitCode)
	}
	fmt.Fprintf(os.Stderr, "\n")
	if len(p) == 0 {
		toggledlog.Fatal.Println(colorRed + "Password is empty" + colorReset)
		os.Exit(exitCode)
	}
	return string(p)
}

// readPasswordStdin reads a line from stdin
// Exits on read error or empty result.
func readPasswordStdin() string {
	toggledlog.Info.Println("Reading password from stdin")
	p := readLineUnbuffered(os.Stdin)
	if len(p) == 0 {
		fmt.Fprintf(os.Stderr, "FOOOOOO\n")
		toggledlog.Fatal.Println(colorRed + "Got empty password from stdin" + colorReset)
		os.Exit(exitCode)
	}
	return p
}

// readPasswordExtpass executes the "extpass" program and returns the first line
// of the output.
// Exits on read error or empty result.
func readPasswordExtpass(extpass string) string {
	toggledlog.Info.Println("Reading password from extpass program")
	parts := strings.Split(extpass, " ")
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		toggledlog.Fatal.Printf(colorRed+"extpass pipe setup failed: %v\n"+colorReset, err)
		os.Exit(exitCode)
	}
	err = cmd.Start()
	if err != nil {
		toggledlog.Fatal.Printf(colorRed+"extpass cmd start failed: %v\n"+colorReset, err)
		os.Exit(exitCode)
	}
	p := readLineUnbuffered(pipe)
	pipe.Close()
	cmd.Wait()
	if len(p) == 0 {
		toggledlog.Fatal.Println(colorRed + "extpass: password is empty" + colorReset)
		os.Exit(exitCode)
	}
	return p
}

// readLineUnbuffered reads single bytes from "r" util it gets "\n" or EOF.
// The returned string does NOT contain the trailing "\n".
func readLineUnbuffered(r io.Reader) (l string) {
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if err == io.EOF {
			return l
		}
		if err != nil {
			toggledlog.Fatal.Printf(colorRed+"readLineUnbuffered: %v\n"+colorReset, err)
			os.Exit(exitCode)
		}
		if n == 0 {
			continue
		}
		if b[0] == '\n' {
			return l
		}
		l = l + string(b)
	}
}
