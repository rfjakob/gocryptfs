package main

import (
	"flag"
	"os"
	"strconv"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/prefer_openssl"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// argContainer stores the parsed CLI options and arguments
type argContainer struct {
	debug, init, zerokey, fusedebug, openssl, passwd, foreground, version,
	plaintextnames, quiet, nosyslog, wpanic,
	longnames, allow_other, ro, reverse, aessiv bool
	masterkey, mountpoint, cipherdir, cpuprofile, extpass,
	memprofile, o string
	// Configuration file name override
	config             string
	notifypid, scryptn int
}

var flagSet *flag.FlagSet

// parseCliOpts - parse command line options (i.e. arguments that start with "-")
func parseCliOpts() (args argContainer) {
	var err error
	var opensslAuto string

	flagSet = flag.NewFlagSet(tlog.ProgramName, flag.ExitOnError)
	flagSet.Usage = usageText
	flagSet.BoolVar(&args.debug, "d", false, "")
	flagSet.BoolVar(&args.debug, "debug", false, "Enable debug output")
	flagSet.BoolVar(&args.fusedebug, "fusedebug", false, "Enable fuse library debug output")
	flagSet.BoolVar(&args.init, "init", false, "Initialize encrypted directory")
	flagSet.BoolVar(&args.zerokey, "zerokey", false, "Use all-zero dummy master key")
	// Tri-state true/false/auto
	flagSet.StringVar(&opensslAuto, "openssl", "auto", "Use OpenSSL instead of built-in Go crypto")
	flagSet.BoolVar(&args.passwd, "passwd", false, "Change password")
	flagSet.BoolVar(&args.foreground, "f", false, "Stay in the foreground")
	flagSet.BoolVar(&args.version, "version", false, "Print version and exit")
	flagSet.BoolVar(&args.plaintextnames, "plaintextnames", false, "Do not encrypt file names")
	flagSet.BoolVar(&args.quiet, "q", false, "")
	flagSet.BoolVar(&args.quiet, "quiet", false, "Quiet - silence informational messages")
	flagSet.BoolVar(&args.nosyslog, "nosyslog", false, "Do not redirect output to syslog when running in the background")
	flagSet.BoolVar(&args.wpanic, "wpanic", false, "When encountering a warning, panic and exit immediately")
	flagSet.BoolVar(&args.longnames, "longnames", true, "Store names longer than 176 bytes in extra files")
	flagSet.BoolVar(&args.allow_other, "allow_other", false, "Allow other users to access the filesystem. "+
		"Only works if user_allow_other is set in /etc/fuse.conf.")
	flagSet.BoolVar(&args.ro, "ro", false, "Mount the filesystem read-only")
	flagSet.BoolVar(&args.reverse, "reverse", false, "Reverse mode")
	flagSet.BoolVar(&args.aessiv, "aessiv", false, "AES-SIV encryption")
	flagSet.StringVar(&args.masterkey, "masterkey", "", "Mount with explicit master key")
	flagSet.StringVar(&args.cpuprofile, "cpuprofile", "", "Write cpu profile to specified file")
	flagSet.StringVar(&args.memprofile, "memprofile", "", "Write memory profile to specified file")
	flagSet.StringVar(&args.config, "config", "", "Use specified config file instead of CIPHERDIR/gocryptfs.conf")
	flagSet.StringVar(&args.extpass, "extpass", "", "Use external program for the password prompt")
	flagSet.StringVar(&args.o, "o", "", "Pass additional mount options to the kernel, comma-separated list")
	flagSet.IntVar(&args.notifypid, "notifypid", 0, "Send USR1 to the specified process after "+
		"successful mount - used internally for daemonization")
	flagSet.IntVar(&args.scryptn, "scryptn", configfile.ScryptDefaultLogN, "scrypt cost parameter logN. "+
		"Setting this to a lower value speeds up mounting but makes the password susceptible to brute-force attacks")
	flagSet.Parse(os.Args[1:])

	// "-openssl" needs some post-processing
	if opensslAuto == "auto" {
		args.openssl = prefer_openssl.PreferOpenSSL()
	} else {
		args.openssl, err = strconv.ParseBool(opensslAuto)
		if err != nil {
			tlog.Fatal.Printf("Invalid \"-openssl\" setting: %v", err)
			os.Exit(ERREXIT_USAGE)
		}
	}

	return args
}
