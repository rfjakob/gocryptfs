// gocryptfs is an encrypted overlay filesystem written in Go.
// See README.md ( https://github.com/rfjakob/gocryptfs/blob/master/README.md )
// and the official website ( https://nuetzlich.net/gocryptfs/ ) for details.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fido2"
	"github.com/rfjakob/gocryptfs/v2/internal/readpassword"
	"github.com/rfjakob/gocryptfs/v2/internal/speed"
	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// GitVersion is the gocryptfs version according to git, set by build.bash
var GitVersion = "[GitVersion not set - please compile using ./build.bash]"

// GitVersionFuse is the go-fuse library version, set by build.bash
var GitVersionFuse = "[GitVersionFuse not set - please compile using ./build.bash]"

// BuildDate is a date string like "2017-09-06", set by build.bash
var BuildDate = "0000-00-00"

// raceDetector is set to true by race.go if we are compiled with "go build -race"
var raceDetector bool

// loadConfig loads the config file `args.config` and decrypts the masterkey,
// or gets via the `-masterkey` or `-zerokey` command line options, if specified.
func loadConfig(args *argContainer) (masterkey []byte, cf *configfile.ConfFile, err error) {
	// First check if the file can be read at all.
	cf, err = configfile.Load(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot open config file: %v", err)
		return nil, nil, err
	}
	// The user may have passed the master key on the command line (probably because
	// he forgot the password).
	masterkey = handleArgsMasterkey(args)
	if masterkey != nil {
		return masterkey, cf, nil
	}
	var pw []byte
	if cf.IsFeatureFlagSet(configfile.FlagFIDO2) {
		if args.fido2 == "" {
			tlog.Fatal.Printf("Masterkey encrypted using FIDO2 token; need to use the --fido2 option.")
			os.Exit(exitcodes.Usage)
		}
		pw = fido2.Secret(args.fido2, cf.FIDO2.CredentialID, cf.FIDO2.HMACSalt)
	} else {
		pw = readpassword.Once([]string(args.extpass), []string(args.passfile), "")
	}
	tlog.Info.Println("Decrypting master key")
	masterkey, err = cf.DecryptMasterKey(pw)
	for i := range pw {
		pw[i] = 0
	}

	if err != nil {
		tlog.Fatal.Println(err)
		return nil, nil, err
	}
	return masterkey, cf, nil
}

// changePassword - change the password of config file "filename"
// Does not return (calls os.Exit both on success and on error).
func changePassword(args *argContainer) {
	var confFile *configfile.ConfFile
	{
		var masterkey []byte
		var err error
		masterkey, confFile, err = loadConfig(args)
		if err != nil {
			exitcodes.Exit(err)
		}
		if len(masterkey) == 0 {
			log.Panic("empty masterkey")
		}
		if confFile.IsFeatureFlagSet(configfile.FlagFIDO2) {
			tlog.Fatal.Printf("Password change is not supported on FIDO2-enabled filesystems.")
			os.Exit(exitcodes.Usage)
		}
		tlog.Info.Println("Please enter your new password.")
		newPw := readpassword.Twice([]string(args.extpass), []string(args.passfile))
		logN := confFile.ScryptObject.LogN()
		if args._explicitScryptn {
			logN = args.scryptn
		}
		confFile.EncryptKey(masterkey, newPw, logN)
		for i := range newPw {
			newPw[i] = 0
		}
		for i := range masterkey {
			masterkey[i] = 0
		}
		// masterkey and newPw run out of scope here
	}
	// Are we resetting the password without knowing the old one using
	// "-masterkey"?
	if args.masterkey != "" {
		bak := args.config + ".bak"
		err := os.Link(args.config, bak)
		if err != nil {
			tlog.Fatal.Printf("Could not create backup file: %v", err)
			os.Exit(exitcodes.Init)
		}
		tlog.Info.Printf(tlog.ColorGrey+
			"A copy of the old config file has been created at %q.\n"+
			"Delete it after you have verified that you can access your files with the new password."+
			tlog.ColorReset, bak)
	}
	err := confFile.WriteFile()
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.WriteConf)
	}
	tlog.Info.Printf(tlog.ColorGreen + "Password changed." + tlog.ColorReset)
}

// printVersion prints a version string like this:
// gocryptfs v1.7-32-gcf99cfd; go-fuse v1.0.0-174-g22a9cb9; 2019-05-12 go1.12 linux/amd64
func printVersion() {
	var tagsSlice []string
	if stupidgcm.BuiltWithoutOpenssl {
		tagsSlice = append(tagsSlice, "without_openssl")
	}
	tags := ""
	if tagsSlice != nil {
		tags = " " + strings.Join(tagsSlice, " ")
	}
	built := fmt.Sprintf("%s %s", BuildDate, runtime.Version())
	if raceDetector {
		built += " -race"
	}
	fmt.Printf("%s %s%s; go-fuse %s; %s %s/%s\n",
		tlog.ProgramName, GitVersion, tags, GitVersionFuse, built,
		runtime.GOOS, runtime.GOARCH)
}

func main() {
	mxp := runtime.GOMAXPROCS(0)
	if mxp < 4 && os.Getenv("GOMAXPROCS") == "" {
		// On a 2-core machine, setting maxprocs to 4 gives 10% better performance.
		// But don't override an explicitly set GOMAXPROCS env variable.
		runtime.GOMAXPROCS(4)
	}
	// mount(1) unsets PATH. Since exec.Command does not handle this case, we set
	// PATH to a default value if it's empty or unset.
	if os.Getenv("PATH") == "" {
		os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	}
	// Show microseconds in go-fuse debug output (-fusedebug)
	log.SetFlags(log.Lmicroseconds)
	var err error
	// Parse all command-line options (i.e. arguments starting with "-")
	// into "args". Path arguments are parsed below.
	args := parseCliOpts(os.Args)
	// Fork a child into the background if "-fg" is not set AND we are mounting
	// a filesystem. The child will do all the work.
	if !args.fg && flagSet.NArg() == 2 {
		ret := forkChild()
		os.Exit(ret)
	}
	if args.debug {
		tlog.Debug.Enabled = true
	}
	tlog.Debug.Printf("cli args: %q", os.Args)
	// "-v"
	if args.version {
		tlog.Debug.Printf("openssl=%v\n", args.openssl)
		tlog.Debug.Printf("on-disk format %d\n", contentenc.CurrentVersion)
		printVersion()
		os.Exit(0)
	}
	// "-hh"
	if args.hh {
		helpLong()
		os.Exit(0)
	}
	// "-speed"
	if args.speed {
		printVersion()
		speed.Run()
		os.Exit(0)
	}
	if args.wpanic {
		tlog.Warn.Wpanic = true
		tlog.Debug.Printf("Panicking on warnings")
	}
	// Every operation below requires CIPHERDIR. Exit if we don't have it.
	if flagSet.NArg() == 0 {
		if flagSet.NFlag() == 0 {
			// Naked call to "gocryptfs". Just print the help text.
			helpShort()
		} else {
			// The user has passed some flags, but CIPHERDIR is missing. State
			// what is wrong.
			tlog.Fatal.Printf("CIPHERDIR argument is missing")
		}
		os.Exit(exitcodes.Usage)
	}
	// Check that CIPHERDIR exists
	args.cipherdir, _ = filepath.Abs(flagSet.Arg(0))
	err = isDir(args.cipherdir)
	if err != nil {
		tlog.Fatal.Printf("Invalid cipherdir: %v", err)
		os.Exit(exitcodes.CipherDir)
	}
	// "-q"
	if args.quiet {
		tlog.Info.Enabled = false
	}
	// "-reverse" implies "-aessiv"
	if args.reverse {
		args.aessiv = true
	} else {
		if args.exclude != nil {
			tlog.Fatal.Printf("-exclude only works in reverse mode")
			os.Exit(exitcodes.ExcludeError)
		}
	}
	// "-config"
	if args.config != "" {
		args.config, err = filepath.Abs(args.config)
		if err != nil {
			tlog.Fatal.Printf("Invalid \"-config\" setting: %v", err)
			os.Exit(exitcodes.Init)
		}
		tlog.Info.Printf("Using config file at custom location %s", args.config)
		args._configCustom = true
	} else if args.reverse {
		args.config = filepath.Join(args.cipherdir, configfile.ConfReverseName)
	} else {
		args.config = filepath.Join(args.cipherdir, configfile.ConfDefaultName)
	}
	// "-force_owner"
	if args.force_owner != "" {
		var uidNum, gidNum int64
		ownerPieces := strings.SplitN(args.force_owner, ":", 2)
		if len(ownerPieces) != 2 {
			tlog.Fatal.Printf("force_owner must be in form UID:GID")
			os.Exit(exitcodes.Usage)
		}
		uidNum, err = strconv.ParseInt(ownerPieces[0], 0, 32)
		if err != nil || uidNum < 0 {
			tlog.Fatal.Printf("force_owner: Unable to parse UID %v as positive integer", ownerPieces[0])
			os.Exit(exitcodes.Usage)
		}
		gidNum, err = strconv.ParseInt(ownerPieces[1], 0, 32)
		if err != nil || gidNum < 0 {
			tlog.Fatal.Printf("force_owner: Unable to parse GID %v as positive integer", ownerPieces[1])
			os.Exit(exitcodes.Usage)
		}
		args._forceOwner = &fuse.Owner{Uid: uint32(uidNum), Gid: uint32(gidNum)}
	}
	// "-cpuprofile"
	if args.cpuprofile != "" {
		onExitFunc := setupCpuprofile(args.cpuprofile)
		defer onExitFunc()
	}
	// "-memprofile"
	if args.memprofile != "" {
		onExitFunc := setupMemprofile(args.memprofile)
		defer onExitFunc()
	}
	// "-trace"
	if args.trace != "" {
		onExitFunc := setupTrace(args.trace)
		defer onExitFunc()
	}
	if args.cpuprofile != "" || args.memprofile != "" || args.trace != "" {
		tlog.Info.Printf("Note: You must unmount gracefully, otherwise the profile file(s) will stay empty!\n")
	}
	// Operation flags
	nOps := countOpFlags(&args)
	if nOps == 0 {
		// Default operation: mount.
		if flagSet.NArg() != 2 {
			prettyArgs := prettyArgs()
			tlog.Info.Printf("Wrong number of arguments (have %d, want 2). You passed: %s",
				flagSet.NArg(), prettyArgs)
			tlog.Fatal.Printf("Usage: %s [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]", tlog.ProgramName)
			os.Exit(exitcodes.Usage)
		}
		doMount(&args)
		// Don't call os.Exit to give deferred functions a chance to run
		return
	}
	if nOps > 1 {
		tlog.Fatal.Printf("At most one of -info, -init, -passwd, -fsck is allowed")
		os.Exit(exitcodes.Usage)
	}
	if flagSet.NArg() != 1 {
		tlog.Fatal.Printf("The options -info, -init, -passwd, -fsck take exactly one argument, %d given",
			flagSet.NArg())
		os.Exit(exitcodes.Usage)
	}
	// "-info"
	if args.info {
		info(args.config)
		os.Exit(0)
	}
	// "-init"
	if args.init {
		initDir(&args)
		os.Exit(0)
	}
	// "-passwd"
	if args.passwd {
		changePassword(&args)
		os.Exit(0)
	}
	// "-fsck"
	if args.fsck {
		code := fsck(&args)
		os.Exit(code)
	}
}
