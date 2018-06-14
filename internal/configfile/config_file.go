// Package configfile reads and writes gocryptfs.conf does the key
// wrapping.
package configfile

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/tlog"
	"github.com/xaionaro-go/trezor"
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
	// TrezorKeyname is a string that is passed to Trezor as a key name
	TrezorKeyname string
	// FeatureFlags is a list of feature flags this filesystem has enabled.
	// If gocryptfs encounters a feature flag it does not support, it will refuse
	// mounting. This mechanism is analogous to the ext4 feature flags that are
	// stored in the superblock.
	FeatureFlags []string
	// Filename is the name of the config file. Not exported to JSON.
	filename string
}

// randBytesDevRandom gets "n" random bytes from /dev/random or panics
func randBytesDevRandom(n int) []byte {
	f, err := os.Open("/dev/random")
	if err != nil {
		log.Panic("Failed to open /dev/random: " + err.Error())
	}
	defer f.Close()
	b := make([]byte, n)
	_, err = io.ReadFull(f, b)
	if err != nil {
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// CreateConfFile - create a new config with a random key encrypted with
// "password" and write it to "filename".
// Uses scrypt with cost parameter logN.
func CreateConfFile(filename string, password []byte, plaintextNames bool, logN int, creator string, aessiv bool, trezorEncryptMasterkey bool, trezorKeyname string, devrandom bool) error {
	var cf ConfFile
	cf.filename = filename
	cf.Creator = creator
	cf.Version = contentenc.CurrentVersion

	// Set feature flags
	cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagGCMIV128])
	cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagHKDF])
	if plaintextNames {
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagPlaintextNames])
	} else {
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagDirIV])
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagEMENames])
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagLongNames])
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagRaw64])
	}
	if aessiv {
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagAESSIV])
	}
	if trezorEncryptMasterkey {
		cf.TrezorKeyname = trezorKeyname
		cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagTrezorEncryptMasterkey])
	}

	{
		// Generate new random master key
		var key []byte
		if devrandom {
			key = randBytesDevRandom(cryptocore.KeyLen)
		} else {
			key = cryptocore.RandBytes(cryptocore.KeyLen)
		}
		if trezorEncryptMasterkey {
			// Encrypt it using a Trezor device
			cf.EncryptKeyByTrezor(key)
		} else {
			// Encrypt it using the password
			// This sets ScryptObject and EncryptedKey
			// Note: this looks at the FeatureFlags, so call it AFTER setting them.
			cf.EncryptKeyByPassword(key, password, logN)
		}
		for i := range key {
			key[i] = 0
		}
		// key runs out of scope here
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
func LoadConfFile(filename string, retrieveMasterKey bool, extpass string) ([]byte, *ConfFile, error) {
	var cf ConfFile
	cf.filename = filename

	// Read from disk
	js, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("LoadConfFile: ReadFile: %#v\n", err)
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

		return nil, nil, exitcodes.NewErr("Deprecated filesystem", exitcodes.DeprecatedFS)
	}

	if !retrieveMasterKey {
		return nil, &cf, nil
	}

	if cf.IsFeatureFlagSet(FlagTrezorEncryptMasterkey) {
		// if `-trezor_encrypt_masterkey` is enabled then the password is passed to a Trezor device
		// directly (via pinentry) and we should ask for it here
		trezor := trezor.New()
		key, err := trezor.DecryptKey(cryptocore.TrezorBIPPath, cf.EncryptedKey, []byte{}, cf.TrezorKeyname)
		return key, &cf, err
	}

	password := readpassword.Once(extpass, "")
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	// Generate derived key from password
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Unlock master key using password-based key
	useHKDF := cf.IsFeatureFlagSet(FlagHKDF)
	ce := getKeyEncrypter(scryptHash, useHKDF)

	tlog.Warn.Enabled = false // Silence DecryptBlock() error messages on incorrect password
	key, err := ce.DecryptBlock(cf.EncryptedKey, 0, nil)
	tlog.Warn.Enabled = true
	if err != nil {
		tlog.Warn.Printf("failed to unlock master key: %s", err.Error())
		return nil, nil, exitcodes.NewErr("Password incorrect.", exitcodes.PasswordIncorrect)
	}

	return key, &cf, err
}


func (cf *ConfFile) EncryptKeyByTrezor(key []byte) {
	trezorInstance := trezor.New()
	cf.EncryptedKey = trezorInstance.EncryptKey(cryptocore.TrezorBIPPath, key, []byte{}, cf.TrezorKeyname)
}
// EncryptKeyByPassword - encrypt "key" using an scrypt hash generated from "password"
// and store it in cf.EncryptedKey.
// Uses scrypt with cost parameter logN and stores the scrypt parameters in
// cf.ScryptObject.
func (cf *ConfFile) EncryptKeyByPassword(key []byte, password []byte, logN int) {
	// Generate scrypt-derived key from password
	cf.ScryptObject = NewScryptKDF(logN)
	scryptHash := cf.ScryptObject.DeriveKey(password)
	// Lock master key using password-based key
	useHKDF := cf.IsFeatureFlagSet(FlagHKDF)
	ce := getKeyEncrypter(scryptHash, useHKDF)
	cf.EncryptedKey = ce.EncryptBlock(key, 0, nil)
	// Purge scrypt-derived key
	for i := range scryptHash {
		scryptHash[i] = 0
	}
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

// getKeyEncrypter is a helper function that returns the right ContentEnc
// instance for the "useHKDF" setting.
func getKeyEncrypter(scryptHash []byte, useHKDF bool) *contentenc.ContentEnc {
	IVLen := 96
	// gocryptfs v1.2 and older used 96-bit IVs for master key encryption.
	// v1.3 adds the "HKDF" feature flag, which also enables 128-bit nonces.
	if useHKDF {
		IVLen = contentenc.DefaultIVBits
	}
	cc := cryptocore.New(scryptHash, cryptocore.BackendGoGCM, IVLen, useHKDF, false)
	ce := contentenc.New(cc, 4096, false)
	return ce
}
