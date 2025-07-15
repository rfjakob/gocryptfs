
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

func takeOut(args *argContainer) {
	if flagSet.NArg() != 3 {
		tlog.Fatal.Printf("Usage: %s -takeout CIPHERDIR PATH DESTDIR", tlog.ProgramName)
		os.Exit(exitcodes.Usage)
	}
	cipherdir := flagSet.Arg(0)
	path := flagSet.Arg(1)
	destdir := flagSet.Arg(2)

	masterkey, confFile, err := loadConfig(args)
	if err != nil {
		exitcodes.Exit(err)
	}

	var aeadType cryptocore.AEADTypeEnum
	if args.aessiv {
		aeadType = cryptocore.BackendAESSIV
	} else if args.xchacha {
		if args.openssl {
			aeadType = cryptocore.BackendXChaCha20Poly1305OpenSSL
		} else {
			aeadType = cryptocore.BackendXChaCha20Poly1305
		}
	} else {
		if args.openssl {
			aeadType = cryptocore.BackendOpenSSL
		} else {
			aeadType = cryptocore.BackendGoGCM
		}
	}
	contentEnc := contentenc.New(cryptocore.New(masterkey, aeadType, contentenc.DefaultIVBits, args.hkdf), contentenc.DefaultBS)

	takeOutPath := filepath.Join(cipherdir, path)

	err = filepath.Walk(takeOutPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if path == args.config {
			return nil
		}

		relPath, err := filepath.Rel(cipherdir, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(destdir, relPath)
		err = os.MkdirAll(filepath.Dir(destPath), 0755)
		if err != nil {
			return err
		}

		ciphertext, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var fileID []byte
		var blockNo uint64
		if confFile.IsFeatureFlagSet(configfile.FlagEMENames) {
			// EME names not supported in this simplified example
			return nil
		}
		if confFile.IsFeatureFlagSet(configfile.FlagDirIV) {
			// DirIV not supported in this simplified example
			return nil
		}
		if confFile.IsFeatureFlagSet(configfile.FlagGCMIV128) {
			// GCMIV128 not supported in this simplified example
			return nil
		}


		plaintext, err := contentEnc.DecryptBlocks(ciphertext, blockNo, fileID)
		if err != nil {
			tlog.Warn.Printf("Failed to decrypt %q: %v", path, err)
			return nil
		}

		err = os.WriteFile(destPath, plaintext, info.Mode())
		if err != nil {
			return err
		}

		err = os.Remove(path)
		if err != nil {
			tlog.Warn.Printf("Failed to remove %q: %v", path, err)
		}

		return nil
	})

	if err != nil {
		tlog.Fatal.Printf("Error walking directory: %v", err)
		os.Exit(exitcodes.Walk)
	}

	fmt.Println("Migration complete.")
}
