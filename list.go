package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
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

		// Get the relative path from the cipherdir
		relPath, err := filepath.Rel(cipherdir, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Skip special files
		if info.Name() == nametransform.DirIVFilename || info.Name() == configfile.ConfDefaultName || info.Name() == configfile.ConfReverseName {
			return nil
		}

		// Only list files, not directories, for "git ls-files" behavior
		if info.IsDir() {
			return nil
		}

		// Split the relative encrypted path into components
		encryptedComponents := strings.Split(relPath, string(filepath.Separator))
		decryptedPathParts := make([]string, len(encryptedComponents))

		// Iterate through components to decrypt each part
		for i, comp := range encryptedComponents {
			var iv []byte
			var errIV error

			// Determine the encrypted parent directory for the current component
			var encryptedParentDir string
			if i == 0 {
				// For the first component, the parent is the cipherdir itself
				encryptedParentDir = cipherdir
			} else {
				// For subsequent components, the parent is the path formed by previous encrypted components
				encryptedParentDir = filepath.Join(cipherdir, filepath.Join(encryptedComponents[:i]...))
			}

			// Read the IV for the parent directory
			iv, errIV = nametransform.ReadDirIV(encryptedParentDir)
			if errIV != nil {
				if os.IsNotExist(errIV) || args.plaintextnames {
					// In plaintextnames mode, or if gocryptfs.diriv is missing, use an all-zero IV.
					iv = make([]byte, nametransform.DirIVLen)
				} else {
					tlog.Warn.Printf("Failed to read IV for parent %q of component %q: %v", encryptedParentDir, comp, errIV)
					return nil // Skip this path if IV cannot be read
				}
			}

			// Decrypt the current component name
			decryptedComp, errDecrypt := nameTransform.DecryptName(comp, iv)
			if errDecrypt != nil {
				tlog.Warn.Printf("Failed to decrypt component %q (full encrypted path: %q): %v", comp, path, errDecrypt)
				return nil // Skip this path if decryption fails
			}
			decryptedPathParts[i] = decryptedComp
		}

		// Join the decrypted components to form the full relative decrypted path
		fullDecryptedPath := filepath.Join(decryptedPathParts...)
		fmt.Println(fullDecryptedPath)

		return nil
	})

	if err != nil {
		tlog.Fatal.Printf("Error walking directory: %v", err)
		os.Exit(exitcodes.Walk)
	}
	}

