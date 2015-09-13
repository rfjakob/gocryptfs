package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rfjakob/gocryptfs/cluefs_frontend"
	"github.com/rfjakob/gocryptfs/pathfs_frontend"
	"github.com/rfjakob/gocryptfs/cryptfs"

	bazilfuse "bazil.org/fuse"
	bazilfusefs "bazil.org/fuse/fs"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

const (
	USE_CLUEFS   = false // Use cluefs or pathfs FUSE frontend
	USE_OPENSSL  = true // 3x speed increase
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
)

func main() {
	// Parse command line arguments
	var debug bool
	var init bool
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.BoolVar(&init, "init", false, "Initialize encrypted directory")
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
		dir, _ := filepath.Abs(flag.Arg(0))
		filename := filepath.Join(dir, cryptfs.ConfDefaultName)
		err := cryptfs.CreateConfFile(filename, "test")
		if err != nil {
			fmt.Println(err)
			os.Exit(ERREXIT_INIT)
		}
		os.Exit(0)
	}
	if flag.NArg() < 2 {
		fmt.Printf("usage: %s CIPHERDIR MOUNTPOINT\n", PROGRAM_NAME)
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

	cfname := filepath.Join(cipherdir, cryptfs.ConfDefaultName)
	_, err = os.Stat(cfname)
	if err != nil {
		fmt.Printf("Error: %s not found in CIPHERDIR\n", cryptfs.ConfDefaultName)
		fmt.Printf("Please run \"%s --init %s\" first\n", PROGRAM_NAME, cipherdir)
		os.Exit(ERREXIT_LOADCONF)
	}
	key, err := cryptfs.LoadConfFile(cfname, "test")
	if err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_LOADCONF)
	}

	if USE_CLUEFS {
		cluefsFrontend(key, cipherdir, mountpoint)
	} else {
		pathfsFrontend(key, cipherdir, mountpoint, debug)
	}
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

	fmt.Println("Mounted!")
	state.Serve()
}
