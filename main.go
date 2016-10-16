package main

import (
	"fmt"
	"os"

	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Exit codes
const (
	ErrExitUsage      = 1
	ErrExitMount      = 3
	ErrExitCipherDir  = 6
	ErrExitInit       = 7
	ErrExitLoadConf   = 8
	ErrExitMountPoint = 10
)

const pleaseBuildBash = "[not set - please compile using ./build.bash]"

// GitVersion is the gocryptfs version according to git, set by build.bash
var GitVersion = pleaseBuildBash

// GitVersionFuse is the go-fuse library version, set by build.bash
var GitVersionFuse = pleaseBuildBash

// BuildTime is the Unix timestamp, set by build.bash
var BuildTime = "0"

func usageText() {
	printVersion()
	fmt.Printf(`
Usage: %s -init|-passwd [OPTIONS] CIPHERDIR
  or   %s [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]

Options:
`, tlog.ProgramName, tlog.ProgramName)

	flagSet.PrintDefaults()
}

// loadConfig loads the config file "args.config", prompting the user for the password
func loadConfig(args *argContainer) (masterkey []byte, confFile *configfile.ConfFile) {
	// Check if the file can be opened at all before prompting for a password
	fd, err := os.Open(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot open config file: %v", err)
		os.Exit(ErrExitLoadConf)
	}
	fd.Close()
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
		os.Exit(ErrExitLoadConf)
	}
	return masterkey, confFile
}

// changePassword - change the password of config file "filename"
func changePassword(args *argContainer) {
	masterkey, confFile := loadConfig(args)
	tlog.Info.Println("Please enter your new password.")
	newPw := readpassword.Twice(args.extpass)
	confFile.EncryptKey(masterkey, newPw, confFile.ScryptObject.LogN())
	if args.masterkey != "" {
		bak := args.config + ".bak"
		err := os.Link(args.config, bak)
		if err != nil {
			tlog.Fatal.Printf("Could not create backup file: %v", err)
			os.Exit(ErrExitInit)
		}
		tlog.Info.Printf(tlog.ColorGrey+
			"A copy of the old config file has been created at %q.\n"+
			"Delete it after you have verified that you can access your files with the new password."+
			tlog.ColorReset, bak)
	}
	err := confFile.WriteFile()
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(ErrExitInit)
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
	fmt.Printf("%s %s%s; go-fuse %s; %s\n",
		tlog.ProgramName, GitVersion, buildFlags, GitVersionFuse, built)
}

func main() {
	runtime.GOMAXPROCS(4)
	var err error
	// Parse all command-line options (i.e. arguments starting with "-")
	// into "args". Path arguments are parsed below.
	args := parseCliOpts()
	// Fork a child into the background if "-f" is not set AND we are mounting
	// a filesystem. The child will do all the work.
	if !args.foreground && flagSet.NArg() == 2 {
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
			os.Exit(ErrExitCipherDir)
		}
	} else {
		usageText()
		os.Exit(ErrExitUsage)
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
			os.Exit(ErrExitInit)
		}
		tlog.Info.Printf("Using config file at custom location %s", args.config)
		args._configCustom = true
	} else if args.reverse {
		args.config = filepath.Join(args.cipherdir, configfile.ConfReverseName)
	} else {
		args.config = filepath.Join(args.cipherdir, configfile.ConfDefaultName)
	}
	// "-cpuprofile"
	if args.cpuprofile != "" {
		tlog.Info.Printf("Writing CPU profile to %s", args.cpuprofile)
		var f *os.File
		f, err = os.Create(args.cpuprofile)
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(ErrExitInit)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	// "-memprofile"
	if args.memprofile != "" {
		tlog.Info.Printf("Writing mem profile to %s", args.memprofile)
		var f *os.File
		f, err = os.Create(args.memprofile)
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(ErrExitInit)
		}
		defer func() {
			pprof.WriteHeapProfile(f)
			f.Close()
			return
		}()
	}
	if args.cpuprofile != "" || args.memprofile != "" {
		tlog.Info.Printf("Note: You must unmount gracefully, otherwise the profile file(s) will stay empty!\n")
	}
	// "-openssl"
	if !args.openssl {
		tlog.Debug.Printf("OpenSSL disabled, using Go GCM")
	} else {
		tlog.Debug.Printf("OpenSSL enabled")
	}
	// Operation flags: -init or -passwd; otherwise: mount
	// "-init"
	if args.init {
		if flagSet.NArg() > 1 {
			tlog.Fatal.Printf("Usage: %s -init [OPTIONS] CIPHERDIR", tlog.ProgramName)
			os.Exit(ErrExitUsage)
		}
		initDir(&args) // does not return
	}
	// "-passwd"
	if args.passwd {
		if flagSet.NArg() > 1 {
			tlog.Fatal.Printf("Usage: %s -passwd [OPTIONS] CIPHERDIR", tlog.ProgramName)
			os.Exit(ErrExitUsage)
		}
		changePassword(&args) // does not return
	}
	// Default operation: mount.
	if flagSet.NArg() != 2 {
		prettyArgs := prettyArgs()
		tlog.Info.Printf("Wrong number of arguments (have %d, want 2). You passed: %s",
			flagSet.NArg(), prettyArgs)
		tlog.Fatal.Printf("Usage: %s [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]", tlog.ProgramName)
		os.Exit(ErrExitUsage)
	}
	os.Exit(doMount(&args))
}
