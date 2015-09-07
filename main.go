package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rfjakob/gocryptfs/cluefs_frontend"
	"github.com/rfjakob/gocryptfs/pathfs_frontend"

	bazilfuse "bazil.org/fuse"
	bazilfusefs "bazil.org/fuse/fs"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
)

const (
	USE_CLUEFS   = false
	USE_OPENSSL  = false
	PATHFS_DEBUG = false

	PROGRAM_NAME = "gocryptfs"

	ERREXIT_USAGE  = 1
	ERREXIT_NEWFS  = 2
	ERREXIT_MOUNT  = 3
	ERREXIT_SERVE  = 4
	ERREXIT_MOUNT2 = 5
)

func main() {
	// Parse command line arguments
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Printf("NArg=%d\n", flag.NArg())
		fmt.Printf("usage: %s CIPHERDIR MOUNTPOINT\n", PROGRAM_NAME)
		os.Exit(ERREXIT_USAGE)
	}
	cipherdir, _ := filepath.Abs(flag.Arg(0))
	mountpoint, _ := filepath.Abs(flag.Arg(1))

	var key [16]byte

	if USE_CLUEFS {
		cluefsFrontend(key, cipherdir, mountpoint)
	} else {
		pathfsFrontend(key, cipherdir, mountpoint)
	}
}

func cluefsFrontend(key [16]byte, cipherdir string, mountpoint string) {
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

func pathfsFrontend(key [16]byte, cipherdir string, mountpoint string){

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
	state.SetDebug(PATHFS_DEBUG)

	fmt.Println("Mounted!")
	state.Serve()
}
