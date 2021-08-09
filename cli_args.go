package main

// Should be initialized before anything else.
// This import line MUST be in the alphabitcally first source code file of
// package main!
import (
	_ "github.com/rfjakob/gocryptfs/internal/ensurefds012"

	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/integrii/flaggy"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// argContainer stores the parsed CLI options and arguments
type argContainer struct {
	debug, init, zerokey, fusedebug, openssl, passwd, fg, version,
	plaintextnames, quiet, nosyslog, wpanic,
	longnames, allow_other, reverse, aessiv, nonempty, raw64,
	noprealloc, speed, hkdf, serialize_reads, forcedecode, hh, info,
	sharedstorage, devrandom, fsck bool
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

type multipleStrings []string

func (s *multipleStrings) String() string {
	s2 := []string(*s)
	return fmt.Sprint(s2)
}

func (s *multipleStrings) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func (s *multipleStrings) Empty() bool {
	s2 := []string(*s)
	return len(s2) == 0
}

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

	os.Args, err = prefixOArgs(os.Args)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.Usage)
	}

	flaggy.SetName(tlog.ProgramName)
	flaggy.DefaultParser.ShowVersionWithVersionFlag = false

	flaggy.AddPositionalValue(&args.cipherdir, "CIPHERDIR", 1, false, "ciphertext directory")
	flaggy.AddPositionalValue(&args.mountpoint, "MOUNTPOINT", 2, false, "mountpoint")

	flaggy.Bool(&args.debug, "d", "", "")
	flaggy.Bool(&args.debug, "debug", "", "Enable debug output")
	flaggy.Bool(&args.fusedebug, "fusedebug", "", "Enable fuse library debug output")
	flaggy.Bool(&args.init, "init", "", "Initialize encrypted directory")
	flaggy.Bool(&args.zerokey, "zerokey", "", "Use all-zero dummy master key")
	// Tri-state true/false/auto
	opensslAuto := "auto"
	flaggy.String(&opensslAuto, "openssl", "", "Use OpenSSL instead of built-in Go crypto")
	flaggy.Bool(&args.passwd, "passwd", "", "Change password")
	flaggy.Bool(&args.fg, "f", "", "")
	flaggy.Bool(&args.fg, "fg", "", "Stay in the foreground")
	flaggy.Bool(&args.version, "version", "", "Print version and exit")
	flaggy.Bool(&args.plaintextnames, "plaintextnames", "", "Do not encrypt file names")
	flaggy.Bool(&args.quiet, "q", "", "")
	flaggy.Bool(&args.quiet, "quiet", "", "Quiet - silence informational messages")
	flaggy.Bool(&args.nosyslog, "nosyslog", "", "Do not redirect output to syslog when running in the background")
	flaggy.Bool(&args.wpanic, "wpanic", "", "When encountering a warning, panic and exit immediately")
	args.longnames = true
	flaggy.Bool(&args.longnames, "longnames", "", "Store names longer than 176 bytes in extra files")
	flaggy.Bool(&args.allow_other, "allow_other", "", "Allow other users to access the filesystem. "+
		"Only works if user_allow_other is set in /etc/fuse.conf.")
	flaggy.Bool(&args.reverse, "reverse", "", "Reverse mode")
	flaggy.Bool(&args.aessiv, "aessiv", "", "AES-SIV encryption")
	flaggy.Bool(&args.nonempty, "nonempty", "", "Allow mounting over non-empty directories")
	args.raw64 = true
	flaggy.Bool(&args.raw64, "raw64", "", "Use unpadded base64 for file names")
	flaggy.Bool(&args.noprealloc, "noprealloc", "", "Disable preallocation before writing")
	flaggy.Bool(&args.speed, "speed", "", "Run crypto speed test")
	args.hkdf = true
	flaggy.Bool(&args.hkdf, "hkdf", "", "Use HKDF as an additional key derivation step")
	flaggy.Bool(&args.serialize_reads, "serialize_reads", "", "Try to serialize read operations")
	flaggy.Bool(&args.forcedecode, "forcedecode", "", "Force decode of files even if integrity check fails."+
		" Requires gocryptfs to be compiled with openssl support and implies -openssl true")
	flaggy.Bool(&args.hh, "hh", "", "Show this long help text")
	flaggy.Bool(&args.info, "info", "", "Display information about CIPHERDIR")
	flaggy.Bool(&args.sharedstorage, "sharedstorage", "", "Make concurrent access to a shared CIPHERDIR safer")
	flaggy.Bool(&args.devrandom, "devrandom", "", "Use /dev/random for generating master key")
	flaggy.Bool(&args.fsck, "fsck", "", "Run a filesystem check on CIPHERDIR")

	// Mount options with opposites
	flaggy.Bool(&args.dev, "dev", "", "Allow device files")
	flaggy.Bool(&args.nodev, "nodev", "", "Deny device files")
	flaggy.Bool(&args.suid, "suid", "", "Allow suid binaries")
	flaggy.Bool(&args.nosuid, "nosuid", "", "Deny suid binaries")
	flaggy.Bool(&args.exec, "exec", "", "Allow executables")
	flaggy.Bool(&args.noexec, "noexec", "", "Deny executables")
	flaggy.Bool(&args.rw, "rw", "", "Mount the filesystem read-write")
	flaggy.Bool(&args.ro, "ro", "", "Mount the filesystem read-only")
	flaggy.Bool(&args.kernel_cache, "kernel_cache", "", "Enable the FUSE kernel_cache option")
	flaggy.Bool(&args.acl, "acl", "", "Enforce ACLs")

	flaggy.String(&args.masterkey, "masterkey", "", "Mount with explicit master key")
	flaggy.String(&args.cpuprofile, "cpuprofile", "", "Write cpu profile to specified file")
	flaggy.String(&args.memprofile, "memprofile", "", "Write memory profile to specified file")
	flaggy.String(&args.config, "config", "", "Use specified config file instead of CIPHERDIR/gocryptfs.conf")
	flaggy.String(&args.ko, "ko", "", "Pass additional options directly to the kernel, comma-separated list")
	flaggy.String(&args.ctlsock, "ctlsock", "", "Create control socket at specified path")
	flaggy.String(&args.fsname, "fsname", "", "Override the filesystem name")
	flaggy.String(&args.force_owner, "force_owner", "", "uid:gid pair to coerce ownership")
	flaggy.String(&args.trace, "trace", "", "Write execution trace to file")
	flaggy.String(&args.fido2, "fido2", "", "Protect the masterkey using a FIDO2 token instead of a password")

	// Exclusion options
	flaggy.StringSlice(&args.exclude, "e", "exclude", "Exclude relative path from reverse view")
	flaggy.StringSlice(&args.excludeWildcard, "ew", "exclude-wildcard", "Exclude path from reverse view, supporting wildcards")
	flaggy.StringSlice(&args.excludeFrom, "exclude-from", "", "File from which to read exclusion patterns (with -exclude-wildcard syntax)")

	// multipleStrings options ([]string)
	flaggy.StringSlice(&args.extpass, "extpass", "", "Use external program for the password prompt")
	flaggy.StringSlice(&args.badname, "badname", "", "Glob pattern invalid file names that should be shown")
	flaggy.StringSlice(&args.passfile, "passfile", "", "Read password from file")

	flaggy.Int(&args.notifypid, "notifypid", "", "Send USR1 to the specified process after "+
		"successful mount - used internally for daemonization")
	const scryptn = "scryptn"
	args.scryptn = configfile.ScryptDefaultLogN
	flaggy.Int(&args.scryptn, scryptn, "", "scrypt cost parameter logN. Possible values: 10-28. "+
		"A lower value speeds up mounting and reduces its memory needs, but makes the password susceptible to brute-force attacks")

	flaggy.Duration(&args.idle, "i", "idle", "Auto-unmount after specified idle duration (ignored in reverse mode). "+
		"Durations are specified like \"500s\" or \"2h45m\". 0 means stay mounted indefinitely.")

	var nofail bool
	flaggy.Bool(&nofail, "nofail", "", "Ignored for /etc/fstab compatibility")

	var dummyString string
	flaggy.String(&dummyString, "o", "", "For compatibility with mount(1), options can be also passed as a comma-separated list to -o on the end.")
	// Actual parsing
	err = flaggy.DefaultParser.Parse()
	if err != nil {
		helpShort()
		os.Exit(0)
	}
	if err != nil {
		tlog.Fatal.Printf("Invalid command line: %s. Try '%s -help'.", prettyArgs(), tlog.ProgramName)
		os.Exit(exitcodes.Usage)
	}
	// We want to know if -scryptn was passed explicitly
	if false /* TODO isFlagPassed(flaggy, scryptn)*/ {
		args._explicitScryptn = true
	}
	// "-openssl" needs some post-processing
	if opensslAuto == "auto" {
		args.openssl = stupidgcm.PreferOpenSSL()
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

// isFlagPassed finds out if the flag was explictely passed on the command line.
// https://stackoverflow.com/a/54747682/1380267
/* TODO
func isFlagPassed(flaggy *flag.flaggy, name string) bool {
	found := false
	flaggy.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
*/
