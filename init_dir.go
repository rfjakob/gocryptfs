package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// initDir prepares a directory for use as a gocryptfs storage directory.
// In forward mode, this means creating the gocryptfs.conf and gocryptfs.diriv
// files in an empty directory.
// In reverse mode, we create .gocryptfs.reverse.conf and the directory does
// not to be empty.
func initDir(args *argContainer) {
	var err error
	if args.reverse {
		_, err = os.Stat(args.config)
		if err == nil {
			tlog.Fatal.Printf("Config file %q already exists", args.config)
			os.Exit(ErrExitInit)
		}
	} else {
		err = checkDirEmpty(args.cipherdir)
		if err != nil {
			tlog.Fatal.Printf("Invalid cipherdir: %v", err)
			os.Exit(ErrExitInit)
		}
	}
	// Choose password for config file
	if args.extpass == "" {
		tlog.Info.Printf("Choose a password for protecting your files.")
	}
	password := readpassword.Twice(args.extpass)
	readpassword.CheckTrailingGarbage()
	creator := tlog.ProgramName + " " + GitVersion
	err = configfile.CreateConfFile(args.config, password, args.plaintextnames, args.scryptn, creator, args.aessiv, args.raw64)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(ErrExitInit)
	}
	// Forward mode with filename encryption enabled needs a gocryptfs.diriv
	// in the root dir
	if !args.plaintextnames && !args.reverse {
		err = nametransform.WriteDirIV(args.cipherdir)
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(ErrExitInit)
		}
	}
	mountArgs := ""
	fsName := "gocryptfs"
	if args.reverse {
		mountArgs = " -reverse"
		fsName = "gocryptfs-reverse"
	}
	tlog.Info.Printf(tlog.ColorGreen+"The %s filesystem has been created successfully."+tlog.ColorReset,
		fsName)
	wd, _ := os.Getwd()
	friendlyPath, _ := filepath.Rel(wd, args.cipherdir)
	if strings.HasPrefix(friendlyPath, "../") {
		// A relative path that starts with "../" is pretty unfriendly, just
		// keep the absolute path.
		friendlyPath = args.cipherdir
	}
	if strings.Contains(friendlyPath, " ") {
		friendlyPath = "\"" + friendlyPath + "\""
	}
	tlog.Info.Printf(tlog.ColorGrey+"You can now mount it using: %s%s %s MOUNTPOINT"+tlog.ColorReset,
		tlog.ProgramName, mountArgs, friendlyPath)
	os.Exit(0)
}
