package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fido2"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/readpassword"
	"github.com/rfjakob/gocryptfs/v2/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// isEmptyDir checks if "dir" exists and is an empty directory.
// Returns an *os.PathError if Stat() on the path fails.
func isEmptyDir(dir string) error {
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
		err = isEmptyDir(args.cipherdir)
		if err != nil {
			tlog.Fatal.Printf("Invalid cipherdir: %v", err)
			os.Exit(exitcodes.CipherDir)
		}
		if !args.xchacha && !stupidgcm.CpuHasAES() {
			tlog.Info.Printf(tlog.ColorYellow +
				"Notice: Your CPU does not have AES acceleration. Consider using -xchacha for better performance." +
				tlog.ColorReset)
		}
	}
	// Choose password for config file
	if len(args.extpass) == 0 && args.fido2 == "" {
		tlog.Info.Printf("Choose a password for protecting your files.")
	}
	{
		var password []byte
		var fido2CredentialID, fido2HmacSalt []byte
		if args.fido2 != "" {
			fido2CredentialID = fido2.Register(args.fido2, filepath.Base(args.cipherdir))
			fido2HmacSalt = cryptocore.RandBytes(32)
			password = fido2.Secret(args.fido2, fido2CredentialID, fido2HmacSalt)
		} else {
			// normal password entry
			password = readpassword.Twice([]string(args.extpass), []string(args.passfile))
			fido2CredentialID = nil
			fido2HmacSalt = nil
		}
		creator := tlog.ProgramName + " " + GitVersion
		err = configfile.Create(&configfile.CreateArgs{
			Filename:           args.config,
			Password:           password,
			PlaintextNames:     args.plaintextnames,
			LogN:               args.scryptn,
			Creator:            creator,
			AESSIV:             args.aessiv,
			Fido2CredentialID:  fido2CredentialID,
			Fido2HmacSalt:      fido2HmacSalt,
			DeterministicNames: args.deterministic_names,
			XChaCha20Poly1305:  args.xchacha,
			LongNameMax:        args.longnamemax,
		})
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
	if !args.plaintextnames && !args.reverse && !args.deterministic_names {
		// Open cipherdir (following symlinks)
		dirfd, err := syscall.Open(args.cipherdir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err == nil {
			err = nametransform.WriteDirIVAt(dirfd)
			syscall.Close(dirfd)
		}
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
