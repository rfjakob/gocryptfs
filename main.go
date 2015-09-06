package main

import (
	"path/filepath"
	"flag"
	"os"
	"fmt"
	"github.com/rfjakob/gocryptfs/frontend"
	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"

)

const (
	PROGRAM_NAME = "gocryptfs"
	USE_OPENSSL = true

	ERREXIT_USAGE = 1
	ERREXIT_NEWFS = 2
	ERREXIT_MOUNT = 3
	ERREXIT_SERVE = 4
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
	mountpoint, err := filepath.Abs(flag.Arg(1))

	// Create the file system object
	var key [16]byte
	cfs, err := frontend.NewFS(key, cipherdir, USE_OPENSSL)
	if err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_NEWFS)
	}

	// Mount the file system
	mountOpts := []fuse.MountOption{
		fuse.FSName(PROGRAM_NAME),
		fuse.Subtype(PROGRAM_NAME),
		fuse.VolumeName(PROGRAM_NAME),
		fuse.LocalVolume(),
		fuse.MaxReadahead(1024*1024),
	}
	conn, err := fuse.Mount(mountpoint, mountOpts...)
	if err != nil {
		fmt.Println(err)
		os.Exit(ERREXIT_MOUNT)
	}
	defer conn.Close()

	// Start serving requests
	if err = fusefs.Serve(conn, cfs); err != nil {
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
