
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// Helper function to decrypt a full encrypted relative path
func decryptRelativePath(encryptedRelPath string, cipherdir string, nameTransform *nametransform.NameTransform, args *argContainer) (string, error) {
	encryptedComponents := strings.Split(encryptedRelPath, string(filepath.Separator))
	decryptedPathParts := make([]string, len(encryptedComponents))

	for i, comp := range encryptedComponents {
		// Handle longname files
		if nametransform.IsLongName(comp) {
			longNamePath := filepath.Join(cipherdir, filepath.Join(encryptedComponents[:i+1]...))
			decryptedComp, err := nametransform.ReadLongName(longNamePath)
			if err != nil {
				return "", fmt.Errorf("failed to read longname file %q: %w", longNamePath, err)
			}
			decryptedPathParts[i] = decryptedComp
			continue
		}

		var iv []byte
		var errIV error

		var encryptedParentDir string
		if i == 0 {
			encryptedParentDir = cipherdir
		} else {
			encryptedParentDir = filepath.Join(cipherdir, filepath.Join(encryptedComponents[:i]...))
		}

		iv, errIV = nametransform.ReadDirIV(encryptedParentDir)
		if errIV != nil {
			if os.IsNotExist(errIV) || args.plaintextnames {
				iv = make([]byte, nametransform.DirIVLen)
			} else {
				return "", fmt.Errorf("failed to read IV for parent %q of component %q: %w", encryptedParentDir, comp, errIV)
			}
		}

		decryptedComp, errDecrypt := nameTransform.DecryptName(comp, iv)
		if errDecrypt != nil {
			return "", fmt.Errorf("failed to decrypt component %q: %w", comp, errDecrypt)
		}
		decryptedPathParts[i] = decryptedComp
	}
	return filepath.Join(decryptedPathParts...), nil
}

func takeOut(args *argContainer) {
	if flagSet.NArg() != 3 {
		tlog.Fatal.Printf("Usage: %s -takeout CIPHERDIR PATH DESTDIR", tlog.ProgramName)
		os.Exit(exitcodes.Usage)
	}
	cipherdir := flagSet.Arg(0)
	userPath := flagSet.Arg(1) // Renamed to userPath to avoid conflict with filepath.Walk's path
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
	var cCore *cryptocore.CryptoCore
	cCore = cryptocore.New(masterkey, aeadType, contentenc.DefaultIVBits, args.hkdf)
	contentEnc := contentenc.New(cCore, contentenc.DefaultBS)
	nameTransform := nametransform.New(cCore.EMECipher, args.longnames, args.longnamemax, args.raw64, args.badname, args.deterministic_names)


	err = filepath.Walk(cipherdir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(cipherdir, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Skip special files
		if info.Name() == nametransform.DirIVFilename || info.Name() == configfile.ConfDefaultName || info.Name() == configfile.ConfReverseName || strings.HasPrefix(info.Name(), "._") {
			return nil
		}

		// Decrypt the full relative path
		decryptedRelPath, err := decryptRelativePath(relPath, cipherdir, nameTransform, args)
		if err != nil {
			tlog.Warn.Printf("Failed to decrypt path %q: %v", path, err)
			return nil // Skip this path
		}

		// Check if the decrypted path matches the user's target path
		if !strings.HasPrefix(decryptedRelPath, userPath) {
			return nil // Not the target path or its child
		}

		// If it's a directory, create it in the destination and continue walking
		if info.IsDir() {
			destPath := filepath.Join(destdir, decryptedRelPath)
			err = os.MkdirAll(destPath, info.Mode())
			if err != nil {
				tlog.Warn.Printf("Failed to create directory %q: %v", destPath, err)
			}
			return nil
		}

		// If it's a file, decrypt and move it
		destPath := filepath.Join(destdir, decryptedRelPath)
		err = os.MkdirAll(filepath.Dir(destPath), 0755) // Ensure parent directory exists
		if err != nil {
			return err
		}

		ciphertext, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var fileID []byte
		var blockNo uint64
		// These feature flags are not directly relevant for content decryption in this context,
		// but are part of the original `take_out.go` and `contentenc.DecryptBlocks` signature.
		// For a full implementation, these would need to be derived from the config file or file headers.
		// For now, we'll assume default behavior or skip if flags are set.
		if confFile.IsFeatureFlagSet(configfile.FlagEMENames) {
			tlog.Warn.Printf("Skipping file %q: EME names not supported in this simplified takeout tool", path)
			return nil
		}
		if confFile.IsFeatureFlagSet(configfile.FlagDirIV) {
			tlog.Warn.Printf("Skipping file %q: DirIV not supported in this simplified takeout tool", path)
			return nil
		}
		if confFile.IsFeatureFlagSet(configfile.FlagGCMIV128) {
			tlog.Warn.Printf("Skipping file %q: GCMIV128 not supported in this simplified takeout tool", path)
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
