package main

import (
	"io/ioutil"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"encoding/hex"
	"runtime"

	"github.com/rfjakob/gocryptfs/cluefs_frontend"
	"github.com/rfjakob/gocryptfs/pathfs_frontend"
	"github.com/rfjakob/gocryptfs/cryptfs"

	"golang.org/x/crypto/ssh/terminal"

	bazilfuse "bazil.org/fuse"
	bazilfusefs "bazil.org/fuse/fs"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

const (
	USE_CLUEFS   = false // Use cluefs or pathfs FUSE frontend
	USE_OPENSSL  = true // 3x speed increase compared to Go's built-in GCM
	PATHFS_DEBUG = false

	PROGRAM_NAME = "gocryptfs"

	// Exit codes
	ERREXIT_USAGE  = 1
	ERREXIT_NEWFS  = 2
	ERREXIT_MOUNT  = 3
	ERREXIT_SERVE  = 4
	ERREXIT_MOUNT2 = 5
	ERREXIT_CIPHERDIR = 6
	ERREXIT_INIT = 7
	ERREXIT_LOADCONF = 8
	ERREXIT_PASSWORD = 9
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

func main() {
	runtime.GOMAXPROCS(4)

	// Parse command line arguments
	var debug, init, zerokey, fusedebug bool

	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.BoolVar(&fusedebug, "fusedebug", false, "Enable fuse library debug output")
	flag.BoolVar(&init, "init", false, "Initialize encrypted directory")
	flag.BoolVar(&zerokey, "zerokey", false, "Use all-zero dummy master key")
	flag.Parse()
	if debug {
		cryptfs.Debug.Enable()
		cryptfs.Debug.Printf("Debug output enabled\n")
	}
	if init {
		if flag.NArg() != 1 {
			fmt.Printf("usage: %s --init CIPHERDIR\n", PROGRAM_NAME)
			os.Exit(ERREXIT_USAGE)
		}
		initDir(flag.Arg(0))
	}
	if flag.NArg() < 2 {
		fmt.Printf("usage: %s [OPTIONS] CIPHERDIR MOUNTPOINT\n", PROGRAM_NAME)
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

	key := make([]byte, cryptfs.KEY_LEN)
	if zerokey {
		fmt.Printf("Zerokey mode active: using all-zero dummy master key.\n")
		fmt.Printf("ZEROKEY MODE PROVIDES NO SECURITY AT ALL.\n")
	} else {
		cfname := filepath.Join(cipherdir, cryptfs.ConfDefaultName)
		_, err = os.Stat(cfname)
		if err != nil {
			fmt.Printf("Error: %s not found in CIPHERDIR\n", cryptfs.ConfDefaultName)
			fmt.Printf("Please run \"%s --init %s\" first\n", PROGRAM_NAME, flag.Arg(0))
			os.Exit(ERREXIT_LOADCONF)
		}
		fmt.Printf("Password: ")
		password := readPassword()
		fmt.Printf("\nDecrypting master key... ")
		key, err = cryptfs.LoadConfFile(cfname, password)
		if err != nil {
			fmt.Println(err)
			os.Exit(ERREXIT_LOADCONF)
		}
		fmt.Printf("Success\n")
		printMasterKey(key)
	}

	if USE_CLUEFS {
		cluefsFrontend(key, cipherdir, mountpoint)
	} else {
		pathfsFrontend(key, cipherdir, mountpoint, fusedebug)
	}
}

// printMasterKey - remind the user that he should store the master key in
// a safe place
func printMasterKey(key []byte) {
	h := hex.EncodeToString(key)
	// Make it less scary by splitting it up in chunks
	h = h[0:8] + "-" + h[8:16] + "-" + h[16:24] + "-" + h[24:32]

	fmt.Printf(`
WARNING:
  If the gocryptfs config file becomes corrupted or you ever
  forget your password, there is only one hope for recovery:
  The master key. Print it to a piece of paper and store it in a drawer.

  Master key: %s

`, h)
}

func readPasswordTwice() string {
	fmt.Printf("Password: ")
	p1 := readPassword()
	fmt.Printf("\nRepeat: ")
	p2 := readPassword()
	fmt.Printf("\n")
	if p1 != p2 {
		fmt.Printf("Passwords do not match\n")
		os.Exit(ERREXIT_PASSWORD)
	}
	return p1
}

// Get password from terminal
func readPassword() string {
	fd := int(os.Stdin.Fd())
	p, err := terminal.ReadPassword(fd)
	if err != nil {
		fmt.Printf("Error: Could not read password: %s\n")
		os.Exit(ERREXIT_PASSWORD)
	}
	return string(p)
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

func cluefsFrontend(key []byte, cipherdir string, mountpoint string) {
	cfs, err := cluefs_frontend.NewFS(key, cipherdir, USE_OPENSSL)
	if err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_NEWFS)
	}

	// Mount the file system
	mountOpts := []bazilfuse.MountOption{
		bazilfuse.FSName(PROGRAM_NAME),
		bazilfuse.Subtype(PROGRAM_NAME),
		bazilfuse.VolumeName(PROGRAM_NAME),
		bazilfuse.LocalVolume(),
		bazilfuse.MaxReadahead(1024 * 1024),
	}
	conn, err := bazilfuse.Mount(mountpoint, mountOpts...)
	if err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_MOUNT)
	}
	defer conn.Close()

	// Start serving requests
	if err = bazilfusefs.Serve(conn, cfs); err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_SERVE)
	}

	// Check for errors when mounting the file system
	<-conn.Ready
	if err = conn.MountError; err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_MOUNT2)
	}

	// We are done
	os.Exit(0)
}

func pathfsFrontend(key []byte, cipherdir string, mountpoint string, debug bool){

	finalFs := pathfs_frontend.NewFS(key, cipherdir, USE_OPENSSL)

	opts := &nodefs.Options{
		// These options are to be compatible with libfuse defaults,
		// making benchmarking easier.
		NegativeTimeout: time.Second,
		AttrTimeout:     time.Second,
		EntryTimeout:    time.Second,
	}
	pathFs := pathfs.NewPathNodeFs(finalFs, nil)
	conn := nodefs.NewFileSystemConnector(pathFs.Root(), opts)
	mOpts := &fuse.MountOptions{
		AllowOther: false,
	}
	state, err := fuse.NewServer(conn.RawFS(), mountpoint, mOpts)
	if err != nil {
		fmt.Printf("Mount fail: %v\n", err)
		os.Exit(1)
	}
	state.SetDebug(debug)

	fmt.Println("Mounted.")
	state.Serve()
}
