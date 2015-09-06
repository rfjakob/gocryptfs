package main

import (
	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"fmt"
	"github.com/rfjakob/cluefs/lib/cluefs"
	"github.com/rfjakob/gocryptfs/frontend"
	"os"
)

const (
	PROGRAM_NAME = "gocryptfs"
	USE_OPENSSL = true
)

func main() {
	// Parse command line arguments
	conf, err := cluefs.ParseArguments()
	if err != nil {
		os.Exit(1)
	}

	// Create the file system object
	var key [16]byte
	cfs := frontend.NewFS(key, conf.GetShadowDir(), USE_OPENSSL)

	// Mount the file system
	mountOpts := []fuse.MountOption{
		fuse.FSName(PROGRAM_NAME),
		fuse.Subtype(PROGRAM_NAME),
		fuse.VolumeName(PROGRAM_NAME),
		fuse.LocalVolume(),
		fuse.MaxReadahead(1024*1024),
	}
	conn, err := fuse.Mount(conf.GetMountPoint(), mountOpts...)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer conn.Close()

	// Start serving requests
	if err = fusefs.Serve(conn, cfs); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Check for errors when mounting the file system
	<-conn.Ready
	if err = conn.MountError; err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// We are done
	os.Exit(0)
}
