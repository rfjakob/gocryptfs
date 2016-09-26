package main

import (
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend_reverse"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// Exit codes
	ERREXIT_USAGE      = 1
	ERREXIT_MOUNT      = 3
	ERREXIT_CIPHERDIR  = 6
	ERREXIT_INIT       = 7
	ERREXIT_LOADCONF   = 8
	ERREXIT_MOUNTPOINT = 10
)

const pleaseBuildBash = "[not set - please compile using ./build.bash]"

// gocryptfs version according to git, set by build.bash
var GitVersion = pleaseBuildBash

// go-fuse library version, set by build.bash
var GitVersionFuse = pleaseBuildBash

// Unix timestamp, set by build.bash
var BuildTime = "0"

func usageText() {
	printVersion()
	fmt.Printf(`
Usage: %s -init|-passwd [OPTIONS] CIPHERDIR
  or   %s [OPTIONS] CIPHERDIR MOUNTPOINT

Options:
`, tlog.ProgramName, tlog.ProgramName)

	flagSet.PrintDefaults()
}

// loadConfig - load the config file "filename", prompting the user for the password
func loadConfig(args *argContainer) (masterkey []byte, confFile *configfile.ConfFile) {
	// Check if the file exists at all before prompting for a password
	_, err := os.Stat(args.config)
	if err != nil {
		tlog.Fatal.Printf("Config file not found: %v", err)
		os.Exit(ERREXIT_LOADCONF)
	}
	pw := readpassword.Once(args.extpass)
	tlog.Info.Println("Decrypting master key")
	masterkey, confFile, err = configfile.LoadConfFile(args.config, pw)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(ERREXIT_LOADCONF)
	}

	return masterkey, confFile
}

// changePassword - change the password of config file "filename"
func changePassword(args *argContainer) {
	masterkey, confFile := loadConfig(args)
	tlog.Info.Println("Please enter your new password.")
	newPw := readpassword.Twice(args.extpass)
	confFile.EncryptKey(masterkey, newPw, confFile.ScryptObject.LogN())
	err := confFile.WriteFile()
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(ERREXIT_INIT)
	}
	tlog.Info.Printf("Password changed.")
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
	built := fmt.Sprintf("%s %s", humanTime, runtime.Version())
	fmt.Printf("%s %s; go-fuse %s; %s\n",
		tlog.ProgramName, GitVersion, GitVersionFuse, built)
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
			os.Exit(ERREXIT_CIPHERDIR)
		}
	} else {
		usageText()
		os.Exit(ERREXIT_USAGE)
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
			os.Exit(ERREXIT_INIT)
		}
		tlog.Info.Printf("Using config file at custom location %s", args.config)
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
			os.Exit(ERREXIT_INIT)
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
			os.Exit(ERREXIT_INIT)
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
			os.Exit(ERREXIT_USAGE)
		}
		initDir(&args) // does not return
	}
	// "-passwd"
	if args.passwd {
		if flagSet.NArg() > 1 {
			tlog.Fatal.Printf("Usage: %s -passwd [OPTIONS] CIPHERDIR", tlog.ProgramName)
			os.Exit(ERREXIT_USAGE)
		}
		changePassword(&args) // does not return
	}
	// Mount
	// Check mountpoint
	if flagSet.NArg() != 2 {
		tlog.Fatal.Printf("Usage: %s [OPTIONS] CIPHERDIR MOUNTPOINT", tlog.ProgramName)
		os.Exit(ERREXIT_USAGE)
	}
	args.mountpoint, err = filepath.Abs(flagSet.Arg(1))
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(ERREXIT_MOUNTPOINT)
	}
	err = checkDirEmpty(args.mountpoint)
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(ERREXIT_MOUNTPOINT)
	}
	// Get master key
	var masterkey []byte
	var confFile *configfile.ConfFile
	if args.masterkey != "" {
		// "-masterkey"
		tlog.Info.Printf("Using explicit master key.")
		masterkey = parseMasterKey(args.masterkey)
		tlog.Info.Printf(tlog.ColorYellow +
			"THE MASTER KEY IS VISIBLE VIA \"ps ax\" AND MAY BE STORED IN YOUR SHELL HISTORY!\n" +
			"ONLY USE THIS MODE FOR EMERGENCIES." + tlog.ColorReset)
	} else if args.zerokey {
		// "-zerokey"
		tlog.Info.Printf("Using all-zero dummy master key.")
		tlog.Info.Printf(tlog.ColorYellow +
			"ZEROKEY MODE PROVIDES NO SECURITY AT ALL AND SHOULD ONLY BE USED FOR TESTING." +
			tlog.ColorReset)
		masterkey = make([]byte, cryptocore.KeyLen)
	} else {
		// Load master key from config file
		masterkey, confFile = loadConfig(&args)
		printMasterKey(masterkey)
	}
	// Initialize FUSE server
	tlog.Debug.Printf("cli args: %v", args)
	srv := initFuseFrontend(masterkey, args, confFile)
	tlog.Info.Println(tlog.ColorGreen + "Filesystem mounted and ready." + tlog.ColorReset)
	// We are ready - send USR1 signal to our parent and switch to syslog
	if args.notifypid > 0 {
		sendUsr1(args.notifypid)

		if !args.nosyslog {
			tlog.Info.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_INFO)
			tlog.Debug.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_DEBUG)
			tlog.Warn.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
			tlog.SwitchLoggerToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
		}
	}
	// Wait for SIGINT in the background and unmount ourselves if we get it.
	// This prevents a dangling "Transport endpoint is not connected" mountpoint.
	handleSigint(srv, args.mountpoint)
	// Jump into server loop. Returns when it gets an umount request from the kernel.
	srv.Serve()
	// main exits with code 0
}

// initFuseFrontend - initialize gocryptfs/fusefrontend
// Calls os.Exit on errors
func initFuseFrontend(key []byte, args argContainer, confFile *configfile.ConfFile) *fuse.Server {
	// Reconciliate CLI and config file arguments into a fusefrontend.Args struct
	// that is passed to the filesystem implementation
	cryptoBackend := cryptocore.BackendGoGCM
	if args.openssl {
		cryptoBackend = cryptocore.BackendOpenSSL
	}
	if args.aessiv {
		cryptoBackend = cryptocore.BackendAESSIV
	}
	frontendArgs := fusefrontend.Args{
		Cipherdir:      args.cipherdir,
		Masterkey:      key,
		PlaintextNames: args.plaintextnames,
		LongNames:      args.longnames,
		CryptoBackend:  cryptoBackend,
	}
	// confFile is nil when "-zerokey" or "-masterkey" was used
	if confFile != nil {
		// Settings from the config file override command line args
		frontendArgs.PlaintextNames = confFile.IsFeatureFlagSet(configfile.FlagPlaintextNames)
		if confFile.IsFeatureFlagSet(configfile.FlagAESSIV) {
			frontendArgs.CryptoBackend = cryptocore.BackendAESSIV
		} else if args.reverse {
			tlog.Fatal.Printf("AES-SIV is required by reverse mode, but not enabled in the config file")
			os.Exit(ERREXIT_USAGE)
		}
	}
	// If allow_other is set and we run as root, try to give newly created files to
	// the right user.
	if args.allow_other && os.Getuid() == 0 {
		frontendArgs.PreserveOwner = true
	}
	jsonBytes, _ := json.MarshalIndent(frontendArgs, "", "\t")
	tlog.Debug.Printf("frontendArgs: %s", string(jsonBytes))
	var finalFs pathfs.FileSystem
	if args.reverse {
		finalFs = fusefrontend_reverse.NewFS(frontendArgs)
	} else {
		finalFs = fusefrontend.NewFS(frontendArgs)
	}
	pathFsOpts := &pathfs.PathNodeFsOptions{ClientInodes: true}
	pathFs := pathfs.NewPathNodeFs(finalFs, pathFsOpts)
	fuseOpts := &nodefs.Options{
		// These options are to be compatible with libfuse defaults,
		// making benchmarking easier.
		NegativeTimeout: time.Second,
		AttrTimeout:     time.Second,
		EntryTimeout:    time.Second,
	}
	conn := nodefs.NewFileSystemConnector(pathFs.Root(), fuseOpts)
	var mOpts fuse.MountOptions
	mOpts.AllowOther = false
	if args.allow_other {
		tlog.Info.Printf(tlog.ColorYellow + "The option \"-allow_other\" is set. Make sure the file " +
			"permissions protect your data from unwanted access." + tlog.ColorReset)
		mOpts.AllowOther = true
		// Make the kernel check the file permissions for us
		mOpts.Options = append(mOpts.Options, "default_permissions")
	}
	// Set values shown in "df -T" and friends
	// First column, "Filesystem"
	mOpts.Options = append(mOpts.Options, "fsname="+args.cipherdir)
	// Second column, "Type", will be shown as "fuse." + Name
	mOpts.Name = "gocryptfs"
	if args.reverse {
		mOpts.Name += "-reverse"
	}

	// The kernel enforces read-only operation, we just have to pass "ro".
	// Reverse mounts are always read-only
	if args.ro || args.reverse {
		mOpts.Options = append(mOpts.Options, "ro")
	}
	// Add additional mount options (if any) after the stock ones, so the user has
	// a chance to override them.
	if args.o != "" {
		parts := strings.Split(args.o, ",")
		tlog.Debug.Printf("Adding -o mount options: %v", parts)
		mOpts.Options = append(mOpts.Options, parts...)
	}
	srv, err := fuse.NewServer(conn.RawFS(), args.mountpoint, &mOpts)
	if err != nil {
		tlog.Fatal.Printf("Mount failed: %v", err)
		os.Exit(ERREXIT_MOUNT)
	}
	srv.SetDebug(args.fusedebug)

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	return srv
}

func handleSigint(srv *fuse.Server, mountpoint string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		err := srv.Unmount()
		if err != nil {
			tlog.Warn.Print(err)
			tlog.Info.Printf("Trying lazy unmount")
			cmd := exec.Command("fusermount", "-u", "-z", mountpoint)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
		}
		os.Exit(1)
	}()
}
