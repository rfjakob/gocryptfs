package readpassword

import (
	"bytes"
	"os"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

func readPassFile(passfile string) []byte {
	tlog.Info.Printf("passfile: reading from file %q", passfile)

	// Check file permissions on passfile, only user access permitted
	fileInfo, err := os.Stat(passfile)
	if err != nil {
		tlog.Fatal.Printf("fatal: passfile: could not stat %q: %v", passfile, err)
		os.Exit(exitcodes.ReadPassword)
	}
	md := fileInfo.Mode().String()
	if md != "-rw-------" {
		tlog.Fatal.Printf("fatal: passfile: invalid file permissions on %q(%v), expected -rw-------",passfile,md)
		os.Exit(exitcodes.ReadPassword)
	}

	f, err := os.Open(passfile)
	if err != nil {
		tlog.Fatal.Printf("fatal: passfile: could not open %q: %v", passfile, err)
		os.Exit(exitcodes.ReadPassword)
	}
	defer f.Close()
	// +1 for an optional trailing newline,
	// +2 so we can detect if maxPasswordLen is exceeded.
	buf := make([]byte, maxPasswordLen+2)
	n, err := f.Read(buf)
	if err != nil {
		tlog.Fatal.Printf("fatal: passfile: could not read from %q: %v", passfile, err)
		os.Exit(exitcodes.ReadPassword)
	}
	buf = buf[:n]
	// Split into first line and "trailing garbage"
	lines := bytes.SplitN(buf, []byte("\n"), 2)
	if len(lines[0]) == 0 {
		tlog.Fatal.Printf("fatal: passfile: empty first line in %q", passfile)
		os.Exit(exitcodes.ReadPassword)
	}
	if len(lines[0]) > maxPasswordLen {
		tlog.Fatal.Printf("fatal: passfile: max password length (%d bytes) exceeded", maxPasswordLen)
		os.Exit(exitcodes.ReadPassword)
	}
	if len(lines) > 1 && len(lines[1]) > 0 {
		tlog.Warn.Printf("passfile: ignoring trailing garbage (%d bytes) after first line",
			len(lines[1]))
	}
	return lines[0]
}
