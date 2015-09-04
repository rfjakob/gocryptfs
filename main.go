package main

import (
	"github.com/rfjakob/cluefs/lib/cluefs"
	"github.com/rfjakob/gocryptfs/frontend"
	"os"
)

func main() {
	// Parse command line arguments
	conf, err := cluefs.ParseArguments()
	if err != nil {
		os.Exit(1)
	}

	// Create the file system object
	var key [16]byte
	cfs := frontend.NewFS(key, conf.GetShadowDir())

	// Mount and serve file system requests
	if err = cfs.MountAndServe(conf.GetMountPoint(), conf.GetReadOnly()); err != nil {
		cluefs.ErrlogMain.Printf("could not mount file system [%s]", err)
		os.Exit(3)
	}

	// We are done
	os.Exit(0)
}
