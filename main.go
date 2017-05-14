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

func usageText() {
	printVersion()
	fmt.Printf(`
Usage: %s -init|-passwd [OPTIONS] CIPHERDIR
  or   %s [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]

Options:
`, tlog.ProgramName, tlog.ProgramName)

	flagSet.PrintDefaults()
	fmt.Print(`  --
    	Stop option parsing
`)
}

// loadConfig loads the config file "args.config", prompting the user for the password
func loadConfig(args *argContainer) (masterkey []byte, confFile *configfile.ConfFile, err error) {
	// Check if the file can be opened at all before prompting for a password
	fd, err := os.Open(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot open config file: %v", err)
		return nil, nil, err
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
		os.Exit(exitcodes.Init)
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
	runtime.GOMAXPROCS(4)
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
		usageText()
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
	// "-cpuprofile"
	if args.cpuprofile != "" {
		tlog.Info.Printf("Writing CPU profile to %s", args.cpuprofile)
		var f *os.File
		f, err = os.Create(args.cpuprofile)
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.Init)
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
			os.Exit(exitcodes.Init)
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
