package main

import (
	// Should be initialized before anything else.
	// This import line MUST be in the alphabetically first source code file of
	// package main!
	_ "github.com/rfjakob/gocryptfs/v2/internal/ensurefds012"

	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// argContainer stores the parsed CLI options and arguments
type argContainer struct {
	debug, init, zerokey, fusedebug, openssl, passwd, fg, version,
	plaintextnames, quiet, nosyslog, wpanic,
	longnames, allow_other, reverse, aessiv, nonempty, raw64,
	noprealloc, speed, hkdf, serialize_reads, hh, info,
	sharedstorage, fsck, one_file_system, deterministic_names,
	xchacha bool
	// Mount options with opposites
	dev, nodev, suid, nosuid, exec, noexec, rw, ro, kernel_cache, acl bool
	masterkey, mountpoint, cipherdir, cpuprofile,
	memprofile, ko, ctlsock, fsname, force_owner, trace, fido2 string
	// -extpass, -badname, -passfile can be passed multiple times
	extpass, badname, passfile []string
	// For reverse mode, several ways to specify exclusions. All can be specified multiple times.
	exclude, excludeWildcard, excludeFrom []string
	// Configuration file name override
	config             string
	notifypid, scryptn int
	// Idle time before autounmount
	idle time.Duration
	// -longnamemax (hash encrypted names that are longer than this)
	longnamemax uint8
	// Helper variables that are NOT cli options all start with an underscore
	// _configCustom is true when the user sets a custom config file name.
	_configCustom bool
	// _ctlsockFd stores the control socket file descriptor (ctlsock stores the path)
	_ctlsockFd net.Listener
	// _forceOwner is, if non-nil, a parsed, validated Owner (as opposed to the string above)
	_forceOwner *fuse.Owner
	// _explicitScryptn is true then the user passed "-scryptn=xyz"
	_explicitScryptn bool
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

// convertToDoubleDash converts args like "-debug" (Go stdlib `flag` style)
// into "--debug" (spf13/pflag style).
// gocryptfs v2.1 switched from `flag` to `pflag`, but we obviously want to stay
// cli-compatible, and this is the hack to do it.
func convertToDoubleDash(osArgs []string) (out []string) {
	out = append(out, osArgs...)
	for i, v := range out {
		// Leave "-h" alone so the help text keeps working
		if v == "-h" {
			continue
		}
		// Don't touch anything after "--"
		if v == "--" {
			break
		}
		// Convert "-foo" to "--foo"
		if len(v) >= 2 && v[0] == '-' && v[1] != '-' {
			out[i] = "-" + out[i]
		}
	}
	return out
}

// parseCliOpts - parse command line options (i.e. arguments that start with "-")
func parseCliOpts(osArgs []string) (args argContainer) {
	var err error
	var opensslAuto string

	osArgsPreprocessed, err := prefixOArgs(osArgs)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.Usage)
	}
	osArgsPreprocessed = convertToDoubleDash(osArgsPreprocessed)

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
	flagSet.BoolVar(&args.longnames, "longnames", true, "Store names longer than 175 bytes in extra files")
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
	flagSet.BoolVar(&args.hh, "hh", false, "Show this long help text")
	flagSet.BoolVar(&args.info, "info", false, "Display information about CIPHERDIR")
	flagSet.BoolVar(&args.sharedstorage, "sharedstorage", false, "Make concurrent access to a shared CIPHERDIR safer")
	flagSet.BoolVar(&args.fsck, "fsck", false, "Run a filesystem check on CIPHERDIR")
	flagSet.BoolVar(&args.one_file_system, "one-file-system", false, "Don't cross filesystem boundaries")
	flagSet.BoolVar(&args.deterministic_names, "deterministic-names", false, "Disable diriv file name randomisation")
	flagSet.BoolVar(&args.xchacha, "xchacha", false, "Use XChaCha20-Poly1305 file content encryption")

	// Mount options with opposites
	flagSet.BoolVar(&args.dev, "dev", false, "Allow device files")
	flagSet.BoolVar(&args.nodev, "nodev", false, "Deny device files")
	flagSet.BoolVar(&args.suid, "suid", false, "Allow suid binaries")
	flagSet.BoolVar(&args.nosuid, "nosuid", false, "Deny suid binaries")
	flagSet.BoolVar(&args.exec, "exec", false, "Allow executables")
	flagSet.BoolVar(&args.noexec, "noexec", false, "Deny executables")
	flagSet.BoolVar(&args.rw, "rw", false, "Mount the filesystem read-write")
	flagSet.BoolVar(&args.ro, "ro", false, "Mount the filesystem read-only")
	flagSet.BoolVar(&args.kernel_cache, "kernel_cache", false, "Enable the FUSE kernel_cache option")
	flagSet.BoolVar(&args.acl, "acl", false, "Enforce ACLs")

	flagSet.StringVar(&args.masterkey, "masterkey", "", "Mount with explicit master key")
	flagSet.StringVar(&args.cpuprofile, "cpuprofile", "", "Write cpu profile to specified file")
	flagSet.StringVar(&args.memprofile, "memprofile", "", "Write memory profile to specified file")
	flagSet.StringVar(&args.config, "config", "", "Use specified config file instead of CIPHERDIR/gocryptfs.conf")
	flagSet.StringVar(&args.ko, "ko", "", "Pass additional options directly to the kernel, comma-separated list")
	flagSet.StringVar(&args.ctlsock, "ctlsock", "", "Create control socket at specified path")
	flagSet.StringVar(&args.fsname, "fsname", "", "Override the filesystem name")
	flagSet.StringVar(&args.force_owner, "force_owner", "", "uid:gid pair to coerce ownership")
	flagSet.StringVar(&args.trace, "trace", "", "Write execution trace to file")
	flagSet.StringVar(&args.fido2, "fido2", "", "Protect the masterkey using a FIDO2 token instead of a password")

	// Exclusion options
	flagSet.StringSliceVar(&args.exclude, "e", nil, "Alias for -exclude")
	flagSet.StringSliceVar(&args.exclude, "exclude", nil, "Exclude relative path from reverse view")
	flagSet.StringSliceVar(&args.excludeWildcard, "ew", nil, "Alias for -exclude-wildcard")
	flagSet.StringSliceVar(&args.excludeWildcard, "exclude-wildcard", nil, "Exclude path from reverse view, supporting wildcards")
	flagSet.StringSliceVar(&args.excludeFrom, "exclude-from", nil, "File from which to read exclusion patterns (with -exclude-wildcard syntax)")

	// multipleStrings options ([]string)
	flagSet.StringSliceVar(&args.extpass, "extpass", nil, "Use external program for the password prompt")
	flagSet.StringSliceVar(&args.badname, "badname", nil, "Glob pattern invalid file names that should be shown")
	flagSet.StringSliceVar(&args.passfile, "passfile", nil, "Read password from file")

	flagSet.Uint8Var(&args.longnamemax, "longnamemax", 255, "Hash encrypted names that are longer than this")

	flagSet.IntVar(&args.notifypid, "notifypid", 0, "Send USR1 to the specified process after "+
		"successful mount - used internally for daemonization")
	const scryptn = "scryptn"
	flagSet.IntVar(&args.scryptn, scryptn, configfile.ScryptDefaultLogN, "scrypt cost parameter logN. Possible values: 10-28. "+
		"A lower value speeds up mounting and reduces its memory needs, but makes the password susceptible to brute-force attacks")

	flagSet.DurationVar(&args.idle, "i", 0, "Alias for -idle")
	flagSet.DurationVar(&args.idle, "idle", 0, "Auto-unmount after specified idle duration (ignored in reverse mode). "+
		"Durations are specified like \"500s\" or \"2h45m\". 0 means stay mounted indefinitely.")

	var dummyString string
	flagSet.StringVar(&dummyString, "o", "", "For compatibility with mount(1), options can be also passed as a comma-separated list to -o on the end.")

	// Ignored flags
	{
		var tmp bool
		flagSet.BoolVar(&tmp, "nofail", false, "Ignored for /etc/fstab compatibility")
		flagSet.BoolVar(&tmp, "devrandom", false, "Obsolete, ignored for compatibility")
		flagSet.BoolVar(&tmp, "forcedecode", false, "Obsolete, ignored for compatibility")
	}

	// Actual parsing
	err = flagSet.Parse(osArgsPreprocessed[1:])
	if err == flag.ErrHelp {
		helpShort()
		os.Exit(0)
	}
	if err != nil {
		tlog.Fatal.Printf("Invalid command line: %s: %v. Try '%s -help'.", prettyArgs(), err, tlog.ProgramName)
		os.Exit(exitcodes.Usage)
	}
	// We want to know if -scryptn was passed explicitly
	if isFlagPassed(flagSet, scryptn) {
		args._explicitScryptn = true
	}
	// "-openssl" needs some post-processing
	if opensslAuto == "auto" {
		if args.xchacha {
			args.openssl = stupidgcm.PreferOpenSSLXchacha20poly1305()
		} else {
			args.openssl = stupidgcm.PreferOpenSSLAES256GCM()
		}
	} else {
		args.openssl, err = strconv.ParseBool(opensslAuto)
		if err != nil {
			tlog.Fatal.Printf("Invalid \"-openssl\" setting: %v", err)
			os.Exit(exitcodes.Usage)
		}
	}
	if len(args.extpass) > 0 && len(args.passfile) != 0 {
		tlog.Fatal.Printf("The options -extpass and -passfile cannot be used at the same time")
		os.Exit(exitcodes.Usage)
	}
	if len(args.passfile) != 0 && args.masterkey != "" {
		tlog.Fatal.Printf("The options -passfile and -masterkey cannot be used at the same time")
		os.Exit(exitcodes.Usage)
	}
	if len(args.extpass) > 0 && args.masterkey != "" {
		tlog.Fatal.Printf("The options -extpass and -masterkey cannot be used at the same time")
		os.Exit(exitcodes.Usage)
	}
	if len(args.extpass) > 0 && args.fido2 != "" {
		tlog.Fatal.Printf("The options -extpass and -fido2 cannot be used at the same time")
		os.Exit(exitcodes.Usage)
	}
	if args.idle < 0 {
		tlog.Fatal.Printf("Idle timeout cannot be less than 0")
		os.Exit(exitcodes.Usage)
	}
	// Make sure all badname patterns are valid
	for _, pattern := range args.badname {
		_, err := filepath.Match(pattern, "")
		if err != nil {
			tlog.Fatal.Printf("-badname: invalid pattern %q supplied", pattern)
			os.Exit(exitcodes.Usage)
		}
	}
	if args.longnamemax > 0 && args.longnamemax < 62 {
		tlog.Fatal.Printf("-longnamemax: value %d is outside allowed range 62 ... 255", args.longnamemax)
		os.Exit(exitcodes.Usage)
	}

	return args
}

// prettyArgs pretty-prints the command-line arguments.
func prettyArgs() string {
	pa := fmt.Sprintf("%q", os.Args)
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

// isFlagPassed finds out if the flag was explictely passed on the command line.
// https://stackoverflow.com/a/54747682/1380267
func isFlagPassed(flagSet *flag.FlagSet, name string) bool {
	found := false
	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
