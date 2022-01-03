package readpassword

import (
	"bytes"
	"fmt"
	"os"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// readPassFileConcatenate reads the first line from each file name and
// concatenates the results. The result does not contain any newlines.
func readPassFileConcatenate(passfileSlice []string) (result []byte, err error) {
	for _, e := range passfileSlice {
		add, err := readPassFile(e)
		if err != nil {
			return nil, err
		}
		result = append(result, add...)
	}
	return result, nil
}

// readPassFile reads the first line from the passed file name.
func readPassFile(passfile string) ([]byte, error) {
	tlog.Info.Printf("passfile: reading from file %q", passfile)
	f, err := os.Open(passfile)
	if err != nil {
		return nil, fmt.Errorf("fatal: passfile: could not open %q: %v", passfile, err)
	}
	defer f.Close()
	// +1 for an optional trailing newline,
	// +2 so we can detect if maxPasswordLen is exceeded.
	buf := make([]byte, maxPasswordLen+2)
	n, err := f.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("fatal: passfile: could not read from %q: %v", passfile, err)
	}
	buf = buf[:n]
	// Split into first line and "trailing garbage"
	lines := bytes.SplitN(buf, []byte("\n"), 2)
	if len(lines[0]) == 0 {
		return nil, fmt.Errorf("fatal: passfile: empty first line in %q", passfile)
	}
	if len(lines[0]) > maxPasswordLen {
		return nil, fmt.Errorf("fatal: passfile: max password length (%d bytes) exceeded", maxPasswordLen)
	}
	if len(lines) > 1 && len(lines[1]) > 0 {
		tlog.Warn.Printf("warning: passfile: ignoring trailing garbage (%d bytes) after first line",
			len(lines[1]))
	}
	return lines[0], nil
}
