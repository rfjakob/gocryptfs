package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// isDirEmpty checks if "dir" exists and is an empty directory.
// Returns an *os.PathError if Stat() on the path fails.
func isDirEmpty(dir string) error {
	err := isDir(dir)
	if err != nil {
		return err
	}
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	return fmt.Errorf("directory %s not empty", dir)
}

// isDir checks if "dir" exists and is a directory.
func isDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// initDir handles "gocryptfs -init". It prepares a directory for use as a
// gocryptfs storage directory.
// In forward mode, this means creating the gocryptfs.conf and gocryptfs.diriv
// files in an empty directory.
// In reverse mode, we create .gocryptfs.reverse.conf and the directory does
// not need to be empty.
func initDir(args *argContainer) {
	var err error
	if args.reverse {
		_, err = os.Stat(args.config)
		if err == nil {
			tlog.Fatal.Printf("Config file %q already exists", args.config)
			os.Exit(exitcodes.Init)
		}
	} else {
		err = isDirEmpty(args.cipherdir)
		if err != nil {
			tlog.Fatal.Printf("Invalid cipherdir: %v", err)
			os.Exit(exitcodes.Init)
		}
	}
	// Choose password for config file
	if args.extpass == "" {
		tlog.Info.Printf("Choose a password for protecting your files.")
	}
	{
		var password []byte
		if args.trezor {
			// Get binary data from from Trezor
			password = readpassword.Trezor()
		} else {
			// Normal password entry
			password = readpassword.Twice(args.extpass)
			readpassword.CheckTrailingGarbage()
		}
		creator := tlog.ProgramName + " " + GitVersion
		err = configfile.Create(args.config, password, args.plaintextnames,
			args.scryptn, creator, args.aessiv, args.devrandom, args.trezor)
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.WriteConf)
		}
		for i := range password {
			password[i] = 0
		}
		// password runs out of scope here
	}
	// Forward mode with filename encryption enabled needs a gocryptfs.diriv file
	// in the root dir
	if !args.plaintextnames && !args.reverse {
		err = nametransform.WriteDirIV(nil, args.cipherdir)
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.Init)
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
}
