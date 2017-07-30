package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hanwen/go-fuse/fuse"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/speed"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// GitVersion is the gocryptfs version according to git, set by build.bash
var GitVersion = "[GitVersion not set - please compile using ./build.bash]"

// GitVersionFuse is the go-fuse library version, set by build.bash
var GitVersionFuse = "[GitVersionFuse not set - please compile using ./build.bash]"

// BuildTime is the Unix timestamp, set by build.bash
var BuildTime = "0"

// raceDetector is set to true by race.go if we are compiled with "go build -race"
var raceDetector bool

// loadConfig loads the config file "args.config", prompting the user for the password
func loadConfig(args *argContainer) (masterkey []byte, confFile *configfile.ConfFile, err error) {
	// Check if the file can be opened at all before prompting for a password
	fd, err := os.Open(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot open config file: %v", err)
		return nil, nil, exitcodes.NewErr(err.Error(), exitcodes.OpenConf)
	}
	fd.Close()
	// The user has passed the master key (probably because he forgot the
	// password).
	if args.masterkey != "" {
		masterkey = parseMasterKey(args.masterkey)
		_, confFile, err = configfile.LoadConfFile(args.config, "")
	} else {
		pw := readpassword.Once(args.extpass)
		tlog.Info.Println("Decrypting master key")
		masterkey, confFile, err = configfile.LoadConfFile(args.config, pw)
	}
	if err != nil {
		tlog.Fatal.Println(err)
		return nil, nil, err
	}
	return masterkey, confFile, nil
}

// changePassword - change the password of config file "filename"
func changePassword(args *argContainer) {
	masterkey, confFile, err := loadConfig(args)
	if err != nil {
		exitcodes.Exit(err)
	}
	tlog.Info.Println("Please enter your new password.")
	newPw := readpassword.Twice(args.extpass)
	readpassword.CheckTrailingGarbage()
	confFile.EncryptKey(masterkey, newPw, confFile.ScryptObject.LogN())
	if args.masterkey != "" {
		bak := args.config + ".bak"
		err = os.Link(args.config, bak)
		if err != nil {
			tlog.Fatal.Printf("Could not create backup file: %v", err)
			os.Exit(exitcodes.Init)
		}
		tlog.Info.Printf(tlog.ColorGrey+
			"A copy of the old config file has been created at %q.\n"+
			"Delete it after you have verified that you can access your files with the new password."+
			tlog.ColorReset, bak)
	}
	err = confFile.WriteFile()
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.WriteConf)
	}
	tlog.Info.Printf(tlog.ColorGreen + "Password changed." + tlog.ColorReset)
	os.Exit(0)
}

// printVersion prints a version string like this:
// gocryptfs v0.12-36-ge021b9d-dirty; go-fuse a4c968c; 2016-07-03 go1.6.2
func printVersion() {
	humanTime := "0000-00-00"
	if i, _ := strconv.ParseInt(BuildTime, 10, 64); i > 0 {
		t := time.Unix(i, 0).UTC()
		humanTime = fmt.Sprintf("%d-%02d-%02d", t.Year(), t.Month(), t.Day())
	}
	buildFlags := ""
	if stupidgcm.BuiltWithoutOpenssl {
		buildFlags = " without_openssl"
	}
	built := fmt.Sprintf("%s %s", humanTime, runtime.Version())
	if raceDetector {
		built += " -race"
	}
	fmt.Printf("%s %s%s; go-fuse %s; %s\n",
		tlog.ProgramName, GitVersion, buildFlags, GitVersionFuse, built)
}

func main() {
	mxp := runtime.GOMAXPROCS(0)
	if mxp < 4 {
		// On a 2-core machine, setting maxprocs to 4 gives 10% better performance
		runtime.GOMAXPROCS(4)
	}
	var err error
	// Parse all command-line options (i.e. arguments starting with "-")
	// into "args". Path arguments are parsed below.
	args := parseCliOpts()
	// Fork a child into the background if "-fg" is not set AND we are mounting
	// a filesystem. The child will do all the work.
	if !args.fg && flagSet.NArg() == 2 {
		ret := forkChild()
		os.Exit(ret)
	}
	if args.debug {
		tlog.Debug.Enabled = true
	}
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
		speed.Run()
		os.Exit(0)
	}
	if args.wpanic {
		tlog.Warn.Wpanic = true
		tlog.Debug.Printf("Panicing on warnings")
	}
	// Every operation below requires CIPHERDIR. Check that we have it.
	if flagSet.NArg() >= 1 {
		args.cipherdir, _ = filepath.Abs(flagSet.Arg(0))
		err = checkDir(args.cipherdir)
		if err != nil {
			tlog.Fatal.Printf("Invalid cipherdir: %v", err)
			os.Exit(exitcodes.CipherDir)
		}
	} else {
		helpShort()
		os.Exit(exitcodes.Usage)
	}
	// "-q"
	if args.quiet {
		tlog.Info.Enabled = false
	}
	// "-reverse" implies "-aessiv"
	if args.reverse {
		args.aessiv = true
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
	// "-openssl"
	if !args.openssl {
		tlog.Debug.Printf("OpenSSL disabled, using Go GCM")
	} else {
		tlog.Debug.Printf("OpenSSL enabled")
	}
	// Operation flags
	if args.info && args.init || args.info && args.passwd || args.passwd && args.init {
		tlog.Fatal.Printf("At most one of -info, -init, -passwd is allowed")
		os.Exit(exitcodes.Usage)
	}
	// "-info"
	if args.info {
		if flagSet.NArg() > 1 {
			tlog.Fatal.Printf("Usage: %s -info CIPHERDIR", tlog.ProgramName)
			os.Exit(exitcodes.Usage)
		}
		info(args.config) // does not return
	}
	// "-init"
	if args.init {
		if flagSet.NArg() > 1 {
			tlog.Fatal.Printf("Usage: %s -init [OPTIONS] CIPHERDIR", tlog.ProgramName)
			os.Exit(exitcodes.Usage)
		}
		initDir(&args) // does not return
	}
	// "-passwd"
	if args.passwd {
		if flagSet.NArg() > 1 {
			tlog.Fatal.Printf("Usage: %s -passwd [OPTIONS] CIPHERDIR", tlog.ProgramName)
			os.Exit(exitcodes.Usage)
		}
		changePassword(&args) // does not return
	}
	// Default operation: mount.
	if flagSet.NArg() != 2 {
		prettyArgs := prettyArgs()
		tlog.Info.Printf("Wrong number of arguments (have %d, want 2). You passed: %s",
			flagSet.NArg(), prettyArgs)
		tlog.Fatal.Printf("Usage: %s [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]", tlog.ProgramName)
		os.Exit(exitcodes.Usage)
	}
	ret := doMount(&args)
	if ret != 0 {
		os.Exit(ret)
	}
	// Don't call os.Exit on success to give deferred functions a chance to
	// run
}
