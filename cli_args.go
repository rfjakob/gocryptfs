package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/prefer_openssl"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// argContainer stores the parsed CLI options and arguments
type argContainer struct {
	debug, init, zerokey, fusedebug, openssl, passwd, fg, version,
	plaintextnames, quiet, nosyslog, wpanic,
	longnames, allow_other, reverse, aessiv, nonempty, raw64,
	noprealloc, speed, hkdf, serialize_reads, forcedecode, hh, info,
	sharedstorage, devrandom, fsck, trezor bool
	// Mount options with opposites
	dev, nodev, suid, nosuid, exec, noexec, rw, ro bool
	masterkey, mountpoint, cipherdir, cpuprofile, extpass,
	memprofile, ko, passfile, ctlsock, fsname, force_owner, trace string
	// Configuration file name override
	config             string
	notifypid, scryptn int
	// Helper variables that are NOT cli options all start with an underscore
	// _configCustom is true when the user sets a custom config file name.
	_configCustom bool
	// _ctlsockFd stores the control socket file descriptor (ctlsock stores the path)
	_ctlsockFd net.Listener
	// _forceOwner is, if non-nil, a parsed, validated Owner (as opposed to the string above)
	_forceOwner *fuse.Owner
}

var flagSet *flag.FlagSet

// prefixOArgs transform options passed via "-o foo,bar" into regular options
// like "-foo -bar" and prefixes them to the command line.
// Testcases in TestPrefixOArgs().
func prefixOArgs(osArgs []string) ([]string, error) {
	// Need at least 3, example: gocryptfs -o    foo,bar
	//                               ^ 0    ^ 1    ^ 2
	if len(osArgs) < 3 {
		return osArgs, nil
	}
	// Passing "--" disables "-o" parsing. Ignore element 0 (program name).
	for _, v := range osArgs[1:] {
		if v == "--" {
			return osArgs, nil
		}
	}
	// Find and extract "-o foo,bar"
	var otherArgs, oOpts []string
	for i := 1; i < len(osArgs); i++ {
		if osArgs[i] == "-o" {
			// Last argument?
			if i+1 >= len(osArgs) {
				return nil, fmt.Errorf("The \"-o\" option requires an argument")
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
			os.Exit(exitcodes.Usage)
		}
		newArgs = append(newArgs, "-"+o)
	}
	// Add other arguments
	newArgs = append(newArgs, otherArgs...)
	return newArgs, nil
}

// parseCliOpts - parse command line options (i.e. arguments that start with "-")
func parseCliOpts() (args argContainer) {
	var err error
	var opensslAuto string

	os.Args, err = prefixOArgs(os.Args)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.Usage)
	}

	flagSet = flag.NewFlagSet(tlog.ProgramName, flag.ContinueOnError)
	flagSet.Usage = func() {}
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
	flagSet.BoolVar(&args.reverse, "reverse", false, "Reverse mode")
	flagSet.BoolVar(&args.aessiv, "aessiv", false, "AES-SIV encryption")
	flagSet.BoolVar(&args.nonempty, "nonempty", false, "Allow mounting over non-empty directories")
	flagSet.BoolVar(&args.raw64, "raw64", true, "Use unpadded base64 for file names")
	flagSet.BoolVar(&args.noprealloc, "noprealloc", false, "Disable preallocation before writing")
	flagSet.BoolVar(&args.speed, "speed", false, "Run crypto speed test")
	flagSet.BoolVar(&args.hkdf, "hkdf", true, "Use HKDF as an additional key derivation step")
	flagSet.BoolVar(&args.serialize_reads, "serialize_reads", false, "Try to serialize read operations")
	flagSet.BoolVar(&args.forcedecode, "forcedecode", false, "Force decode of files even if integrity check fails."+
		" Requires gocryptfs to be compiled with openssl support and implies -openssl true")
	flagSet.BoolVar(&args.hh, "hh", false, "Show this long help text")
	flagSet.BoolVar(&args.info, "info", false, "Display information about CIPHERDIR")
	flagSet.BoolVar(&args.sharedstorage, "sharedstorage", false, "Make concurrent access to a shared CIPHERDIR safer")
	flagSet.BoolVar(&args.devrandom, "devrandom", false, "Use /dev/random for generating master key")
	flagSet.BoolVar(&args.fsck, "fsck", false, "Run a filesystem check on CIPHERDIR")
	flagSet.BoolVar(&args.trezor, "trezor", false, "Protect the masterkey using a SatoshiLabs Trezor instead of a password")

	// Mount options with opposites
	flagSet.BoolVar(&args.dev, "dev", false, "Allow device files")
	flagSet.BoolVar(&args.nodev, "nodev", false, "Deny device files")
	flagSet.BoolVar(&args.suid, "suid", false, "Allow suid binaries")
	flagSet.BoolVar(&args.nosuid, "nosuid", false, "Deny suid binaries")
	flagSet.BoolVar(&args.exec, "exec", false, "Allow executables")
	flagSet.BoolVar(&args.noexec, "noexec", false, "Deny executables")
	flagSet.BoolVar(&args.rw, "rw", false, "Mount the filesystem read-write")
	flagSet.BoolVar(&args.ro, "ro", false, "Mount the filesystem read-only")

	flagSet.StringVar(&args.masterkey, "masterkey", "", "Mount with explicit master key")
	flagSet.StringVar(&args.cpuprofile, "cpuprofile", "", "Write cpu profile to specified file")
	flagSet.StringVar(&args.memprofile, "memprofile", "", "Write memory profile to specified file")
	flagSet.StringVar(&args.config, "config", "", "Use specified config file instead of CIPHERDIR/gocryptfs.conf")
	flagSet.StringVar(&args.extpass, "extpass", "", "Use external program for the password prompt")
	flagSet.StringVar(&args.passfile, "passfile", "", "Read password from file")
	flagSet.StringVar(&args.ko, "ko", "", "Pass additional options directly to the kernel, comma-separated list")
	flagSet.StringVar(&args.ctlsock, "ctlsock", "", "Create control socket at specified path")
	flagSet.StringVar(&args.fsname, "fsname", "", "Override the filesystem name")
	flagSet.StringVar(&args.force_owner, "force_owner", "", "uid:gid pair to coerce ownership")
	flagSet.StringVar(&args.trace, "trace", "", "Write execution trace to file")
	flagSet.IntVar(&args.notifypid, "notifypid", 0, "Send USR1 to the specified process after "+
		"successful mount - used internally for daemonization")
	flagSet.IntVar(&args.scryptn, "scryptn", configfile.ScryptDefaultLogN, "scrypt cost parameter logN. Possible values: 10-28. "+
		"A lower value speeds up mounting and reduces its memory needs, but makes the password susceptible to brute-force attacks")
	var dummyString string
	flagSet.StringVar(&dummyString, "o", "", "For compatibility with mount(1), options can be also passed as a comma-separated list to -o on the end.")
	// Actual parsing
	err = flagSet.Parse(os.Args[1:])
	if err == flag.ErrHelp {
		helpShort()
		os.Exit(0)
	}
	if err != nil {
		tlog.Fatal.Printf("Invalid command line: %s. Try '%s -help'.", prettyArgs(), tlog.ProgramName)
		os.Exit(exitcodes.Usage)
	}
	// "-openssl" needs some post-processing
	if opensslAuto == "auto" {
		args.openssl = prefer_openssl.PreferOpenSSL()
	} else {
		args.openssl, err = strconv.ParseBool(opensslAuto)
		if err != nil {
			tlog.Fatal.Printf("Invalid \"-openssl\" setting: %v", err)
			os.Exit(exitcodes.Usage)
		}
	}
	// "-forcedecode" only works with openssl. Check compilation and command line parameters
	if args.forcedecode == true {
		if stupidgcm.BuiltWithoutOpenssl == true {
			tlog.Fatal.Printf("The -forcedecode flag requires openssl support, but gocryptfs was compiled without it!")
			os.Exit(exitcodes.Usage)
		}
		if args.aessiv == true {
			tlog.Fatal.Printf("The -forcedecode and -aessiv flags are incompatible because they use different crypto libs (openssl vs native Go)")
			os.Exit(exitcodes.Usage)
		}
		if args.reverse == true {
			tlog.Fatal.Printf("The reverse mode and the -forcedecode option are not compatible")
			os.Exit(exitcodes.Usage)
		}
		// Has the user explicitly disabled openssl using "-openssl=false/0"?
		if !args.openssl && opensslAuto != "auto" {
			tlog.Fatal.Printf("-forcedecode requires openssl, but is disabled via command-line option")
			os.Exit(exitcodes.Usage)
		}
		args.openssl = true

		// Try to make it harder for the user to shoot himself in the foot.
		args.ro = true
		args.allow_other = false
		args.ko = "noexec"
	}
	// '-passfile FILE' is a shortcut for -extpass='/bin/cat -- FILE'
	if args.passfile != "" {
		args.extpass = "/bin/cat -- " + args.passfile
	}
	if args.extpass != "" && args.masterkey != "" {
		tlog.Fatal.Printf("The options -extpass and -masterkey cannot be used at the same time")
		os.Exit(exitcodes.Usage)
	}
	return args
}

// prettyArgs pretty-prints the command-line arguments.
func prettyArgs() string {
	pa := fmt.Sprintf("%v", os.Args)
	// Get rid of "[" and "]"
	pa = pa[1 : len(pa)-1]
	return pa
}

// countOpFlags counts the number of operation flags we were passed.
func countOpFlags(args *argContainer) int {
	var count int
	if args.info {
		count++
	}
	if args.passwd {
		count++
	}
	if args.init {
		count++
	}
	if args.fsck {
		count++
	}
	return count
}
