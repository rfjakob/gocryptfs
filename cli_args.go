package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/prefer_openssl"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// argContainer stores the parsed CLI options and arguments
type argContainer struct {
	debug, init, zerokey, fusedebug, openssl, passwd, fg, version,
	plaintextnames, quiet, nosyslog, wpanic,
	longnames, allow_other, ro, reverse, aessiv, nonempty, raw64,
	noprealloc bool
	masterkey, mountpoint, cipherdir, cpuprofile, extpass,
	memprofile, ko, passfile, ctlsock string
	// Configuration file name override
	config             string
	notifypid, scryptn int
	// _configCustom is true when the user sets a custom config file name.
	// This is not a CLI option.
	_configCustom bool
}

var flagSet *flag.FlagSet

// prefixOArgs transform options passed via "-o foo,bar" into regular options
// like "-foo -bar" and prefixes them to the command line.
func prefixOArgs(osArgs []string) []string {
	// Need at least 3, example: gocryptfs -o foo,bar
	if len(osArgs) < 3 {
		return osArgs
	}
	// Find and extract "-o foo,bar"
	var otherArgs, oOpts []string
	for i := 1; i < len(osArgs); i++ {
		if osArgs[i] == "-o" {
			// Last argument?
			if i+1 >= len(osArgs) {
				tlog.Fatal.Printf("The \"-o\" option requires an argument")
				os.Exit(ErrExitUsage)
			}
			oOpts = strings.Split(osArgs[i+1], ",")
			// Skip over the arguments to "-o"
			i++
		} else if strings.HasPrefix(osArgs[i], "-o=") {
			oOpts = strings.Split(osArgs[i][3:], ",")
		} else {
			otherArgs = append(otherArgs, osArgs[i])
		}
	}
	// Start with program name
	newArgs := []string{osArgs[0]}
	// Add options from "-o"
	for _, o := range oOpts {
		if o == "" {
			continue
		}
		if o == "o" || o == "-o" {
			tlog.Fatal.Printf("You can't pass \"-o\" to \"-o\"")
			os.Exit(ErrExitUsage)
		}
		newArgs = append(newArgs, "-"+o)
	}
	// Add other arguments
	newArgs = append(newArgs, otherArgs...)
	return newArgs
}

// parseCliOpts - parse command line options (i.e. arguments that start with "-")
func parseCliOpts() (args argContainer) {
	os.Args = prefixOArgs(os.Args)

	var err error
	var opensslAuto string

	flagSet = flag.NewFlagSet(tlog.ProgramName, flag.ContinueOnError)
	flagSet.Usage = usageText
	flagSet.BoolVar(&args.debug, "d", false, "")
	flagSet.BoolVar(&args.debug, "debug", false, "Enable debug output")
	flagSet.BoolVar(&args.fusedebug, "fusedebug", false, "Enable fuse library debug output")
	flagSet.BoolVar(&args.init, "init", false, "Initialize encrypted directory")
	flagSet.BoolVar(&args.zerokey, "zerokey", false, "Use all-zero dummy master key")
	// Tri-state true/false/auto
	flagSet.StringVar(&opensslAuto, "openssl", "auto", "Use OpenSSL instead of built-in Go crypto")
	flagSet.BoolVar(&args.passwd, "passwd", false, "Change password")
	flagSet.BoolVar(&args.fg, "f", false, "")
	flagSet.BoolVar(&args.fg, "fg", false, "Stay in the foreground")
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
	flagSet.BoolVar(&args.nonempty, "nonempty", false, "Allow mounting over non-empty directories")
	flagSet.BoolVar(&args.raw64, "raw64", false, "Use unpadded base64 for file names")
	flagSet.BoolVar(&args.noprealloc, "noprealloc", false, "Disable preallocation before writing")
	flagSet.StringVar(&args.masterkey, "masterkey", "", "Mount with explicit master key")
	flagSet.StringVar(&args.cpuprofile, "cpuprofile", "", "Write cpu profile to specified file")
	flagSet.StringVar(&args.memprofile, "memprofile", "", "Write memory profile to specified file")
	flagSet.StringVar(&args.config, "config", "", "Use specified config file instead of CIPHERDIR/gocryptfs.conf")
	flagSet.StringVar(&args.extpass, "extpass", "", "Use external program for the password prompt")
	flagSet.StringVar(&args.passfile, "passfile", "", "Read password from file")
	flagSet.StringVar(&args.ko, "ko", "", "Pass additional options directly to the kernel, comma-separated list")
	flagSet.StringVar(&args.ctlsock, "ctlsock", "", "Create control socket at specified path")
	flagSet.IntVar(&args.notifypid, "notifypid", 0, "Send USR1 to the specified process after "+
		"successful mount - used internally for daemonization")
	flagSet.IntVar(&args.scryptn, "scryptn", configfile.ScryptDefaultLogN, "scrypt cost parameter logN. "+
		"A lower value speeds up mounting but makes the password susceptible to brute-force attacks")
	// Ignored otions
	var dummyBool bool
	ignoreText := "(ignored for compatibility)"
	flagSet.BoolVar(&dummyBool, "rw", false, ignoreText)
	flagSet.BoolVar(&dummyBool, "nosuid", false, ignoreText)
	flagSet.BoolVar(&dummyBool, "nodev", false, ignoreText)
	var dummyString string
	flagSet.StringVar(&dummyString, "o", "", "For compatibility, all options can be also passed as a comma-separated list to -o.")
	// Actual parsing
	err = flagSet.Parse(os.Args[1:])
	if err == flag.ErrHelp {
		os.Exit(0)
	}
	if err != nil {
		tlog.Warn.Printf("You passed: %s", prettyArgs())
		tlog.Fatal.Printf("%v", err)
		os.Exit(ErrExitUsage)
	}
	// "-openssl" needs some post-processing
	if opensslAuto == "auto" {
		args.openssl = prefer_openssl.PreferOpenSSL()
	} else {
		args.openssl, err = strconv.ParseBool(opensslAuto)
		if err != nil {
			tlog.Fatal.Printf("Invalid \"-openssl\" setting: %v", err)
			os.Exit(ErrExitUsage)
		}
	}
	// "-passfile FILE" is a shortcut for "-extpass=/bin/cat FILE"
	if args.passfile != "" {
		args.extpass = "/bin/cat " + args.passfile
	}
	if args.extpass != "" && args.masterkey != "" {
		tlog.Fatal.Printf("The options -extpass and -masterkey cannot be used at the same time")
		os.Exit(ErrExitUsage)
	}
	return args
}

// prettyArgs pretty-prints the command-line arguments.
func prettyArgs() string {
	pa := fmt.Sprintf("%q", os.Args[1:])
	// Get rid of "[" and "]"
	pa = pa[1 : len(pa)-1]
	return pa
}
