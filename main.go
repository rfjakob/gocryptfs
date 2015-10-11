package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/rfjakob/gocryptfs/cryptfs"
	"github.com/rfjakob/gocryptfs/pathfs_frontend"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

const (
	USE_OPENSSL  = true
	PATHFS_DEBUG = false

	PROGRAM_NAME = "gocryptfs"

	// Exit codes
	ERREXIT_USAGE     = 1
	ERREXIT_NEWFS     = 2
	ERREXIT_MOUNT     = 3
	ERREXIT_SERVE     = 4
	ERREXIT_MOUNT2    = 5
	ERREXIT_CIPHERDIR = 6
	ERREXIT_INIT      = 7
	ERREXIT_LOADCONF  = 8
	ERREXIT_PASSWORD  = 9
)

func initDir(dirArg string) {
	dir, _ := filepath.Abs(dirArg)

	if dirEmpty(dir) == false {
		fmt.Printf("Error: Directory \"%s\" is not empty\n", dirArg)
		os.Exit(ERREXIT_INIT)
	}

	confName := filepath.Join(dir, cryptfs.ConfDefaultName)
	fmt.Printf("Choose a password for protecting your files.\n")
	password := readPasswordTwice()
	err := cryptfs.CreateConfFile(confName, password)
	if err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_INIT)
	}
	fmt.Printf("The filesystem is now ready for mounting.\n")
	os.Exit(0)
}

func usageText() {
	fmt.Printf("Usage: %s [OPTIONS] CIPHERDIR MOUNTPOINT\n", PROGRAM_NAME)
	fmt.Printf("\nOptions:\n")
	flag.PrintDefaults()
}

func main() {
	runtime.GOMAXPROCS(4)

	// Parse command line arguments
	var debug, init, zerokey, fusedebug, openssl, passwd, foreground bool
	var masterkey string

	flag.Usage = usageText
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.BoolVar(&fusedebug, "fusedebug", false, "Enable fuse library debug output")
	flag.BoolVar(&init, "init", false, "Initialize encrypted directory")
	flag.BoolVar(&zerokey, "zerokey", false, "Use all-zero dummy master key")
	flag.BoolVar(&openssl, "openssl", true, "Use OpenSSL instead of built-in Go crypto")
	flag.BoolVar(&passwd, "passwd", false, "Change password")
	flag.BoolVar(&foreground, "f", false, "Stay in the foreground")
	flag.StringVar(&masterkey, "masterkey", "", "Mount with explicit master key")
	var cpuprofile = flag.String("cpuprofile", "", "Write cpu profile to specified file")

	flag.Parse()
	if ! foreground {
		daemonize() // does not return
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Println(err)
			os.Exit(ERREXIT_INIT)
		}
		fmt.Printf("Writing CPU profile to %s\n", *cpuprofile)
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	if debug {
		cryptfs.Debug.Enable()
		cryptfs.Debug.Printf("Debug output enabled\n")
	}
	if openssl == false {
		fmt.Printf("Openssl disabled\n")
	}
	if init {
		if flag.NArg() != 1 {
			fmt.Printf("Usage: %s --init CIPHERDIR\n", PROGRAM_NAME)
			os.Exit(ERREXIT_USAGE)
		}
		initDir(flag.Arg(0))
	} else if passwd {
		if flag.NArg() != 1 {
			fmt.Printf("Usage: %s --passwd CIPHERDIR\n", PROGRAM_NAME)
			os.Exit(ERREXIT_USAGE)
		}
	} else if flag.NArg() < 2 {
		usageText()
		os.Exit(ERREXIT_USAGE)
	}
	cipherdir, _ := filepath.Abs(flag.Arg(0))
	mountpoint, _ := filepath.Abs(flag.Arg(1))
	cryptfs.Debug.Printf("cipherdir=%s\nmountpoint=%s\n", cipherdir, mountpoint)

	_, err := os.Stat(cipherdir)
	if err != nil {
		fmt.Printf("Cipherdir: %s\n", err.Error())
		os.Exit(ERREXIT_CIPHERDIR)
	}

	var cf *cryptfs.ConfFile
	var currentPassword string
	key := make([]byte, cryptfs.KEY_LEN)
	if zerokey {
		fmt.Printf("Zerokey mode active: using all-zero dummy master key.\n")
	} else if len(masterkey) > 0 {
		key = parseMasterKey(masterkey)
		fmt.Printf("Using explicit master key.\n")
	} else {
		cfname := filepath.Join(cipherdir, cryptfs.ConfDefaultName)
		_, err = os.Stat(cfname)
		if err != nil {
			fmt.Printf("Error: %s not found in CIPHERDIR\n", cryptfs.ConfDefaultName)
			fmt.Printf("Please run \"%s --init %s\" first\n", PROGRAM_NAME, flag.Arg(0))
			os.Exit(ERREXIT_LOADCONF)
		}
		if passwd == true {
			fmt.Printf("Old password: ")
		} else {
			fmt.Printf("Password: ")
		}
		currentPassword = readPassword()
		fmt.Printf("\nDecrypting master key... ")
		cryptfs.Warn.Disable() // Silence DecryptBlock() error messages on incorrect password
		key, cf, err = cryptfs.LoadConfFile(cfname, currentPassword)
		cryptfs.Warn.Enable()
		if err != nil {
			fmt.Println(err)
			fmt.Println("Password incorrect.")
			os.Exit(ERREXIT_LOADCONF)
		}
		fmt.Printf("done.\n")
	}
	if passwd == true {
		fmt.Printf("Please enter the new password.\n")
		newPassword := readPasswordTwice()
		if newPassword == currentPassword {
			fmt.Printf("New and old passwords are identical\n")
			os.Exit(1)
		}
		cf.EncryptKey(key, newPassword)
		err := cf.WriteFile()
		if err != nil {
			fmt.Println(err)
			os.Exit(ERREXIT_INIT)
		}
		fmt.Printf("Password changed.\n")
		os.Exit(0)
	}

	srv := pathfsFrontend(key, cipherdir, mountpoint, fusedebug, openssl)

	if zerokey == false && len(masterkey) == 0 {
		printMasterKey(key)
	} else if zerokey == true {
		fmt.Printf("ZEROKEY MODE PROVIDES NO SECURITY AT ALL AND SHOULD ONLY BE USED FOR TESTING.\n")
	} else if len(masterkey) > 0 {
		fmt.Printf("THE MASTER KEY IS VISIBLE VIA \"ps -auxwww\", ONLY USE THIS MODE FOR EMERGENCIES.\n")
	}

	fmt.Println("Filesystem ready.")
	// Send notification to our parent
	sendUsr1()
	// Jump into server loop
	srv.Serve()
}

func dirEmpty(dir string) bool {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_CIPHERDIR)
	}
	if len(entries) == 0 {
		return true
	}
	return false
}

func pathfsFrontend(key []byte, cipherdir string, mountpoint string, debug bool, openssl bool) *fuse.Server {

	finalFs := pathfs_frontend.NewFS(key, cipherdir, openssl)
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
	// Set values shown in "df -T" and friends
	// First column, "Filesystem"
	mOpts.Options = append(mOpts.Options, "fsname="+cipherdir)
	// Second column, "Type", will be shown as "fuse." + Name
	mOpts.Name = "gocryptfs"

	srv, err := fuse.NewServer(conn.RawFS(), mountpoint, &mOpts)
	if err != nil {
		fmt.Printf("Mount failed: %v", err)
		os.Exit(1)
	}
	srv.SetDebug(debug)

	return srv
}
