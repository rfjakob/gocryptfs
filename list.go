package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

func list(args *argContainer) {
	if flagSet.NArg() != 1 {
		tlog.Fatal.Printf("Usage: %s -list CIPHERDIR", tlog.ProgramName)
		os.Exit(exitcodes.Usage)
	}
	cipherdir := flagSet.Arg(0)

	masterkey, _, err := loadConfig(args)
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
	cCore := cryptocore.New(masterkey, aeadType, 128, args.hkdf)
	nameTransform := nametransform.New(cCore.EMECipher, args.longnames, args.longnamemax, args.raw64, args.badname, args.deterministic_names)

	err = filepath.Walk(cipherdir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(cipherdir, path)
		if err != nil {
			return err
		}

		if relPath == "." {
			fmt.Println(".")
			return nil
		}

		parentDir := filepath.Dir(path)
		iv, err := nametransform.ReadDirIV(parentDir)
		if err != nil {
			if os.IsNotExist(err) || args.plaintextnames {
				// In plaintextnames mode, or if gocryptfs.diriv is missing, we can just use an all-zero IV.
				iv = make([]byte, nametransform.DirIVLen)
			} else {
				tlog.Warn.Printf("Failed to read IV for %q: %v", path, err)
				return nil
			}
		}

		decryptedName, err := nameTransform.DecryptName(info.Name(), iv)
		if err != nil {
			tlog.Warn.Printf("Failed to decrypt name %q: %v", info.Name(), err)
			return nil
		}

		// Simple tree printing
		level := len(filepath.SplitList(relPath))
		indent := ""
		for i := 0; i < level-1; i++ {
			indent += "|   "
		}
		if info.IsDir() {
			fmt.Printf("%s|-- %s/\n", indent, decryptedName)
		} else {
			fmt.Printf("%s|-- %s\n", indent, decryptedName)
		}

		return nil
	})

	if err != nil {
		tlog.Fatal.Printf("Error walking directory: %v", err)
		os.Exit(exitcodes.Walk)
	}
}
