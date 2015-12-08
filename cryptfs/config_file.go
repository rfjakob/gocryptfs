package cryptfs

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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
func CreateConfFile(filename string, password string, plaintextNames bool, logN int, EMENames bool) error {
	var cf ConfFile
	cf.filename = filename

	// Generate new random master key
	key := RandBytes(KEY_LEN)

	// Encrypt it using the password
	// This sets ScryptObject and EncryptedKey
	cf.EncryptKey(key, password, logN)

	// Set defaults
	cf.Version = HEADER_CURRENT_VERSION

	// Set values chosen by the user
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
		Warn.Printf("Failed to unmarshal config file\n")
		return nil, nil, err
	}

	if cf.Version != HEADER_CURRENT_VERSION {
		return nil, nil, fmt.Errorf("Unsupported on-disk format %d\n", cf.Version)
	}

	for _, flag := range cf.FeatureFlags {
		if cf.isFeatureFlagKnown(flag) == false {
			return nil, nil, fmt.Errorf("Unsupported feature flag %s\n", flag)
		}
	}

	// Generate derived key from password
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Unlock master key using password-based key
	// We use stock go GCM instead of OpenSSL here as speed is not important
	// and we get better error messages
	cfs := NewCryptFS(scryptHash, false, false)
	key, err := cfs.DecryptBlock(cf.EncryptedKey, 0, nil)
	if err != nil {
		Warn.Printf("failed to unlock master key: %s\n", err.Error())
		Warn.Printf("Password incorrect.\n")
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
	cfs := NewCryptFS(scryptHash, false, false)
	cf.EncryptedKey = cfs.EncryptBlock(key, 0, nil)
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
	// Also teach isFeatureFlagKnown() about any additions
	FlagPlaintextNames = "PlaintextNames"
	FlagDirIV          = "DirIV"
	FlagEMENames       = "EMENames"
)

// Verify that we understand a feature flag
func (cf *ConfFile) isFeatureFlagKnown(flag string) bool {
	switch flag {
	case FlagPlaintextNames, FlagDirIV, FlagEMENames:
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
