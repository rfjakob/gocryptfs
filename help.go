package main

import (
	"fmt"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const tUsage = "" +
	"Usage: " + tlog.ProgramName + " -init|-passwd|-info [OPTIONS] CIPHERDIR\n" +
	"  or   " + tlog.ProgramName + " [OPTIONS] CIPHERDIR MOUNTPOINT\n"

// helpShort is what gets displayed when passed "-h" or on syntax error.
func helpShort() {
	printVersion()
	fmt.Printf("\n")
	fmt.Printf(tUsage)
	fmt.Printf(`
Common Options (use -hh to show all):
  -aessiv            Use AES-SIV encryption (with -init)
  -allow_other       Allow other users to access the mount
  -i, -idle          Unmount automatically after specified idle duration
  -config            Custom path to config file
  -ctlsock           Create control socket at location
  -extpass           Call external program to prompt for the password
  -fg                Stay in the foreground
  -fsck              Check filesystem integrity
  -fusedebug         Debug FUSE calls
  -h, -help          This short help text
  -hh                Long help text with all options
  -init              Initialize encrypted directory
  -info              Display information about encrypted directory
  -masterkey         Mount with explicit master key instead of password
  -nonempty          Allow mounting over non-empty directory
  -nosyslog          Do not redirect log messages to syslog
  -passfile          Read password from plain text file(s)
  -passwd            Change password
  -plaintextnames    Do not encrypt file names (with -init)
  -q, -quiet         Silence informational messages
  -reverse           Enable reverse mode
  -ro                Mount read-only
  -speed             Run crypto speed test
  -version           Print version information
  --                 Stop option parsing
`)
}

// helpLong gets only displayed on "-hh"
func helpLong() {
	printVersion()
	fmt.Printf("\n")
	fmt.Printf(tUsage)
	fmt.Printf(`
Notes: All options can equivalently use "-" (single dash) or "--" (double dash).
       A standalone "--" stops option parsing.
`)
	fmt.Printf("\nOptions:\n")
	flagSet.PrintDefaults()
}
