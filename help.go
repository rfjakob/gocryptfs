package main

import (
	"fmt"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const tUsage = "" +
	"Usage: " + tlog.ProgramName + " -init|-passwd|-info [OPTIONS] CIPHERDIR\n" +
	"  or   " + tlog.ProgramName + " [OPTIONS] CIPHERDIR MOUNTPOINT\n" +
	"  or   " + tlog.ProgramName + " -init [INIT-OPTIONS] CIPHERDIR -mount [MOUNT-OPTIONS] MOUNTPOINT\n"

// helpShort is what gets displayed when passed "-h" or on syntax error.
func helpShort() {
	printVersion()
	fmt.Print("\n")
	fmt.Print(tUsage)
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
  -mount             Combined with -init: init then mount in one call (see -hh)
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
	fmt.Print("\n")
	fmt.Print(tUsage)
	fmt.Printf(`
Notes: All options can equivalently use "-" (single dash) or "--" (double dash).
       A standalone "--" stops option parsing.

Combined init+mount:
  "-init" and "-mount" can be combined to initialize and mount in a single call:
      ` + tlog.ProgramName + ` -init [INIT-OPTIONS] CIPHERDIR -mount [MOUNT-OPTIONS] MOUNTPOINT
  "-init" must come before "-mount". The command line is split into two
  independent argument sets that are processed in sequence, so options never
  leak between the phases (e.g. "-q" in the init section does not affect the
  mount section). If the init phase fails, the mount phase is not run. The
  password entered during init is reused for the mount.
  If "-init" was given an explicit "-masterkey <key>", a bare "-masterkey" (no
  value) in the mount section reuses that key. An explicit masterkey value in
  the mount section must match the one given to init.
`)
	fmt.Printf("\nOptions:\n")
	flagSet.PrintDefaults()
}
