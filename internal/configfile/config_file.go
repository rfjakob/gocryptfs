package configfile

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/toggledlog"
)
import "os"

const (
	// The dot "." is not used in base64url (RFC4648), hence
	// we can never clash with an encrypted file.
	ConfDefaultName = "gocryptfs.conf"
)

type ConfFile struct {
	// File the config is saved to. Not exported to JSON.
	filename string
	// Encrypted AES key, unlocked using a password hashed with scrypt
	EncryptedKey []byte
	// Stores parameters for scrypt hashing (key derivation)
	ScryptObject scryptKdf
	// The On-Disk-Format version this filesystem uses
	Version uint16
	// List of feature flags this filesystem has enabled.
	// If gocryptfs encounters a feature flag it does not support, it will refuse
	// mounting. This mechanism is analogous to the ext4 feature flags that are
	// stored in the superblock.
	FeatureFlags []string
}

// CreateConfFile - create a new config with a random key encrypted with
// "password" and write it to "filename".
// Uses scrypt with cost parameter logN.
func CreateConfFile(filename string, password string, plaintextNames bool, logN int) error {
	var cf ConfFile
	cf.filename = filename
	cf.Version = contentenc.CurrentVersion

	// Generate new random master key
	key := cryptocore.RandBytes(cryptocore.KeyLen)

	// Encrypt it using the password
	// This sets ScryptObject and EncryptedKey
	cf.EncryptKey(key, password, logN)

	// Set feature flags
	cf.FeatureFlags = append(cf.FeatureFlags, FlagGCMIV128)
	if plaintextNames {
		cf.FeatureFlags = append(cf.FeatureFlags, FlagPlaintextNames)
	} else {
		cf.FeatureFlags = append(cf.FeatureFlags, FlagDirIV)
		cf.FeatureFlags = append(cf.FeatureFlags, FlagEMENames)
	}

	// Write file to disk
	return cf.WriteFile()
}

// LoadConfFile - read config file from disk and decrypt the
// contained key using password.
//
// Returns the decrypted key and the ConfFile object
func LoadConfFile(filename string, password string) ([]byte, *ConfFile, error) {
	var cf ConfFile
	cf.filename = filename

	// Read from disk
	js, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	// Unmarshal
	err = json.Unmarshal(js, &cf)
	if err != nil {
		toggledlog.Warn.Printf("Failed to unmarshal config file")
		return nil, nil, err
	}

	if cf.Version != contentenc.CurrentVersion {
		return nil, nil, fmt.Errorf("Unsupported on-disk format %d", cf.Version)
	}

	for _, flag := range cf.FeatureFlags {
		if cf.isFeatureFlagKnown(flag) == false {
			return nil, nil, fmt.Errorf("Unsupported feature flag %s", flag)
		}
	}

	// Generate derived key from password
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Unlock master key using password-based key
	// We use stock go GCM instead of OpenSSL here as speed is not important
	// and we get better error messages
	cc := cryptocore.New(scryptHash, false, false)
	ce := contentenc.New(cc, 4096)

	key, err := ce.DecryptBlock(cf.EncryptedKey, 0, nil)
	if err != nil {
		toggledlog.Warn.Printf("failed to unlock master key: %s", err.Error())
		toggledlog.Warn.Printf("Password incorrect.")
		return nil, nil, err
	}

	return key, &cf, nil
}

// EncryptKey - encrypt "key" using an scrypt hash generated from "password"
// and store it in cf.EncryptedKey.
// Uses scrypt with cost parameter logN and stores the scrypt parameters in
// cf.ScryptObject.
func (cf *ConfFile) EncryptKey(key []byte, password string, logN int) {
	// Generate derived key from password
	cf.ScryptObject = NewScryptKdf(logN)
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Lock master key using password-based key
	cc := cryptocore.New(scryptHash, false, false)
	ce := contentenc.New(cc, 4096)
	cf.EncryptedKey = ce.EncryptBlock(key, 0, nil)
}

// WriteFile - write out config in JSON format to file "filename.tmp"
// then rename over "filename".
// This way a password change atomically replaces the file.
func (cf *ConfFile) WriteFile() error {
	tmp := cf.filename + ".tmp"
	// 0400 permissions: gocryptfs.conf should be kept secret and never be written to.
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	js, err := json.MarshalIndent(cf, "", "\t")
	if err != nil {
		return err
	}
	_, err = fd.Write(js)
	if err != nil {
		return err
	}
	err = fd.Sync()
	if err != nil {
		return err
	}
	err = fd.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tmp, cf.filename)
	if err != nil {
		return err
	}

	return nil
}

const (
	// Understood Feature Flags.
	// Also teach isFeatureFlagKnown() about any additions and
	// add it to CreateConfFile() if you want to have it enabled by default.
	FlagPlaintextNames = "PlaintextNames"
	FlagDirIV          = "DirIV"
	FlagEMENames       = "EMENames"
	FlagGCMIV128       = "GCMIV128"
)

// Verify that we understand a feature flag
func (cf *ConfFile) isFeatureFlagKnown(flag string) bool {
	switch flag {
	case FlagPlaintextNames, FlagDirIV, FlagEMENames, FlagGCMIV128:
		return true
	default:
		return false
	}
}

// isFeatureFlagSet - is the feature flag "flagWant" enabled?
func (cf *ConfFile) IsFeatureFlagSet(flagWant string) bool {
	if !cf.isFeatureFlagKnown(flagWant) {
		log.Panicf("BUG: Tried to use unsupported feature flag %s", flagWant)
	}
	for _, flag := range cf.FeatureFlags {
		if flag == flagWant {
			return true
		}
	}
	return false
}
