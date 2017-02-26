// Package configfile reads and writes gocryptfs.conf does the key
// wrapping.
package configfile

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)
import "os"

const (
	// ConfDefaultName is the default configuration file name.
	// The dot "." is not used in base64url (RFC4648), hence
	// we can never clash with an encrypted file.
	ConfDefaultName = "gocryptfs.conf"
	// ConfReverseName is the default configuration file name in reverse mode,
	// the config file gets stored next to the plain-text files. Make it hidden
	// (start with dot) to not annoy the user.
	ConfReverseName = ".gocryptfs.reverse.conf"
)

// ConfFile is the content of a config file.
type ConfFile struct {
	// Creator is the gocryptfs version string.
	// This only documents the config file for humans who look at it. The actual
	// technical info is contained in FeatureFlags.
	Creator string
	// EncryptedKey holds an encrypted AES key, unlocked using a password
	// hashed with scrypt
	EncryptedKey []byte
	// ScryptObject stores parameters for scrypt hashing (key derivation)
	ScryptObject ScryptKDF
	// Version is the On-Disk-Format version this filesystem uses
	Version uint16
	// FeatureFlags is a list of feature flags this filesystem has enabled.
	// If gocryptfs encounters a feature flag it does not support, it will refuse
	// mounting. This mechanism is analogous to the ext4 feature flags that are
	// stored in the superblock.
	FeatureFlags []string
	// Filename is the name of the config file. Not exported to JSON.
	filename string
}

// CreateConfFile - create a new config with a random key encrypted with
// "password" and write it to "filename".
// Uses scrypt with cost parameter logN.
func CreateConfFile(filename string, password string, plaintextNames bool, logN int, creator string, aessiv bool, raw64 bool) error {
	var cf ConfFile
	cf.filename = filename
	cf.Creator = creator
	cf.Version = contentenc.CurrentVersion

	// Generate new random master key
	key := cryptocore.RandBytes(cryptocore.KeyLen)

	// Encrypt it using the password
	// This sets ScryptObject and EncryptedKey
	cf.EncryptKey(key, password, logN)

	// Set feature flags
	cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagGCMIV128])
	if plaintextNames {
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagPlaintextNames])
	} else {
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagDirIV])
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagEMENames])
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagLongNames])
		if raw64 {
			cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagRaw64])
		}
	}
	if aessiv {
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagAESSIV])
	}

	// Write file to disk
	return cf.WriteFile()
}

// LoadConfFile - read config file from disk and decrypt the
// contained key using "password".
// Returns the decrypted key and the ConfFile object
//
// If "password" is empty, the config file is read
// but the key is not decrypted (returns nil in its place).
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
		tlog.Warn.Printf("Failed to unmarshal config file")
		return nil, nil, err
	}

	if cf.Version != contentenc.CurrentVersion {
		return nil, nil, fmt.Errorf("Unsupported on-disk format %d", cf.Version)
	}

	// Check that all set feature flags are known
	for _, flag := range cf.FeatureFlags {
		if !cf.isFeatureFlagKnown(flag) {
			return nil, nil, fmt.Errorf("Unsupported feature flag %q", flag)
		}
	}

	// Check that all required feature flags are set
	var requiredFlags []flagIota
	if cf.IsFeatureFlagSet(FlagPlaintextNames) {
		requiredFlags = requiredFlagsPlaintextNames
	} else {
		requiredFlags = requiredFlagsNormal
	}
	deprecatedFs := false
	for _, i := range requiredFlags {
		if !cf.IsFeatureFlagSet(i) {
			fmt.Fprintf(os.Stderr, "Required feature flag %q is missing\n", knownFlags[i])
			deprecatedFs = true
		}
	}
	if deprecatedFs {
		fmt.Fprintf(os.Stderr, "\033[33m"+`
    The filesystem was created by gocryptfs v0.6 or earlier. This version of
    gocryptfs can no longer mount the filesystem.
    Please download gocryptfs v0.11 and upgrade your filesystem,
    see https://github.com/rfjakob/gocryptfs/wiki/Upgrading for instructions.

    If you have trouble upgrading, join the discussion at
    https://github.com/rfjakob/gocryptfs/issues/29 .

`+"\033[0m")

		return nil, nil, fmt.Errorf("Deprecated filesystem")
	}
	if password == "" {
		// We have validated the config file, but without a password we cannot
		// decrypt the master key. Return only the parsed config.
		return nil, &cf, nil
	}
	// Generate derived key from password
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Unlock master key using password-based key
	// We use stock go GCM instead of OpenSSL here as we only use 96-bit IVs,
	// speed is not important and we get better error messages
	cc := cryptocore.New(scryptHash, cryptocore.BackendGoGCM, 96)
	ce := contentenc.New(cc, 4096)

	tlog.Warn.Enabled = false // Silence DecryptBlock() error messages on incorrect password
	key, err := ce.DecryptBlock(cf.EncryptedKey, 0, nil)
	tlog.Warn.Enabled = true
	if err != nil {
		tlog.Warn.Printf("failed to unlock master key: %s", err.Error())
		return nil, nil, exitcodes.NewErr("Password incorrect.", exitcodes.PasswordIncorrect)
	}

	return key, &cf, err
}

// EncryptKey - encrypt "key" using an scrypt hash generated from "password"
// and store it in cf.EncryptedKey.
// Uses scrypt with cost parameter logN and stores the scrypt parameters in
// cf.ScryptObject.
func (cf *ConfFile) EncryptKey(key []byte, password string, logN int) {
	// Generate derived key from password
	cf.ScryptObject = NewScryptKDF(logN)
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Lock master key using password-based key
	cc := cryptocore.New(scryptHash, cryptocore.BackendGoGCM, 96)
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
	// For convenience for the user, add a newline at the end.
	js = append(js, '\n')
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
	return err
}
