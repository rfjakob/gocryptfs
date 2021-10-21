// Package configfile reads and writes gocryptfs.conf does the key
// wrapping.
package configfile

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"syscall"

	"os"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

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

// FIDO2Params is a structure for storing FIDO2 parameters.
type FIDO2Params struct {
	// FIDO2 credential
	CredentialID []byte
	// FIDO2 hmac-secret salt
	HMACSalt []byte
}

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
	// FIDO2 parameters
	FIDO2 *FIDO2Params `json:",omitempty"`
	// LongNameMax corresponds to the -longnamemax flag
	LongNameMax uint8 `json:",omitempty"`
	// Filename is the name of the config file. Not exported to JSON.
	filename string
}

// CreateArgs exists because the argument list to Create became too long.
type CreateArgs struct {
	Filename           string
	Password           []byte
	PlaintextNames     bool
	LogN               int
	Creator            string
	AESSIV             bool
	Fido2CredentialID  []byte
	Fido2HmacSalt      []byte
	DeterministicNames bool
	XChaCha20Poly1305  bool
	LongNameMax        uint8
}

// Create - create a new config with a random key encrypted with
// "Password" and write it to "Filename".
// Uses scrypt with cost parameter "LogN".
func Create(args *CreateArgs) error {
	cf := ConfFile{
		filename: args.Filename,
		Creator:  args.Creator,
		Version:  contentenc.CurrentVersion,
	}
	// Feature flags
	cf.setFeatureFlag(FlagHKDF)
	if args.XChaCha20Poly1305 {
		cf.setFeatureFlag(FlagXChaCha20Poly1305)
	} else {
		// 128-bit IVs are mandatory for AES-GCM (default is 96!) and AES-SIV,
		// XChaCha20Poly1305 uses even an even longer IV of 192 bits.
		cf.setFeatureFlag(FlagGCMIV128)
	}
	if args.PlaintextNames {
		cf.setFeatureFlag(FlagPlaintextNames)
	} else {
		if !args.DeterministicNames {
			cf.setFeatureFlag(FlagDirIV)
		}
		// 0 means to *use* the default (which means we don't have to save it), and
		// 255 *is* the default, which means we don't have to save it either.
		if args.LongNameMax != 0 && args.LongNameMax != 255 {
			cf.LongNameMax = args.LongNameMax
			cf.setFeatureFlag(FlagLongNameMax)
		}
		cf.setFeatureFlag(FlagEMENames)
		cf.setFeatureFlag(FlagLongNames)
		cf.setFeatureFlag(FlagRaw64)
	}
	if args.AESSIV {
		cf.setFeatureFlag(FlagAESSIV)
	}
	if len(args.Fido2CredentialID) > 0 {
		cf.setFeatureFlag(FlagFIDO2)
		cf.FIDO2 = &FIDO2Params{
			CredentialID: args.Fido2CredentialID,
			HMACSalt:     args.Fido2HmacSalt,
		}
	}
	// Catch bugs and invalid cli flag combinations early
	cf.ScryptObject = NewScryptKDF(args.LogN)
	if err := cf.Validate(); err != nil {
		return err
	}
	{
		// Generate new random master key
		key := cryptocore.RandBytes(cryptocore.KeyLen)
		tlog.PrintMasterkeyReminder(key)
		// Encrypt it using the password
		// This sets ScryptObject and EncryptedKey
		// Note: this looks at the FeatureFlags, so call it AFTER setting them.
		cf.EncryptKey(key, args.Password, args.LogN)
		for i := range key {
			key[i] = 0
		}
		// key runs out of scope here
	}
	// Write file to disk
	return cf.WriteFile()
}

// LoadAndDecrypt - read config file from disk and decrypt the
// contained key using "password".
// Returns the decrypted key and the ConfFile object
//
// If "password" is empty, the config file is read
// but the key is not decrypted (returns nil in its place).
func LoadAndDecrypt(filename string, password []byte) ([]byte, *ConfFile, error) {
	cf, err := Load(filename)
	if err != nil {
		return nil, nil, err
	}
	if len(password) == 0 {
		// We have validated the config file, but without a password we cannot
		// decrypt the master key. Return only the parsed config.
		return nil, cf, nil
		// TODO: Make this an error in gocryptfs v1.7. All code should now call
		// Load() instead of calling LoadAndDecrypt() with an empty password.
	}

	// Decrypt the masterkey using the password
	key, err := cf.DecryptMasterKey(password)
	if err != nil {
		return nil, nil, err
	}

	return key, cf, err
}

// Load loads and parses the config file at "filename".
func Load(filename string) (*ConfFile, error) {
	var cf ConfFile
	cf.filename = filename

	// Read from disk
	js, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(js) == 0 {
		return nil, fmt.Errorf("Config file is empty")
	}

	// Unmarshal
	err = json.Unmarshal(js, &cf)
	if err != nil {
		tlog.Warn.Printf("Failed to unmarshal config file")
		return nil, err
	}

	if err := cf.Validate(); err != nil {
		return nil, exitcodes.NewErr(err.Error(), exitcodes.DeprecatedFS)
	}

	// All good
	return &cf, nil
}

func (cf *ConfFile) setFeatureFlag(flag flagIota) {
	if cf.IsFeatureFlagSet(flag) {
		// Already set, ignore
		return
	}
	cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[flag])
}

// DecryptMasterKey decrypts the masterkey stored in cf.EncryptedKey using
// password.
func (cf *ConfFile) DecryptMasterKey(password []byte) (masterkey []byte, err error) {
	// Generate derived key from password
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Unlock master key using password-based key
	useHKDF := cf.IsFeatureFlagSet(FlagHKDF)
	ce := getKeyEncrypter(scryptHash, useHKDF)

	tlog.Warn.Enabled = false // Silence DecryptBlock() error messages on incorrect password
	masterkey, err = ce.DecryptBlock(cf.EncryptedKey, 0, nil)
	tlog.Warn.Enabled = true

	// Purge scrypt-derived key
	for i := range scryptHash {
		scryptHash[i] = 0
	}
	scryptHash = nil
	ce.Wipe()
	ce = nil

	if err != nil {
		tlog.Warn.Printf("failed to unlock master key: %s", err.Error())
		return nil, exitcodes.NewErr("Password incorrect.", exitcodes.PasswordIncorrect)
	}
	return masterkey, nil
}

// EncryptKey - encrypt "key" using an scrypt hash generated from "password"
// and store it in cf.EncryptedKey.
// Uses scrypt with cost parameter logN and stores the scrypt parameters in
// cf.ScryptObject.
func (cf *ConfFile) EncryptKey(key []byte, password []byte, logN int) {
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
	scryptHash = nil
	ce.Wipe()
	ce = nil
}

// WriteFile - write out config in JSON format to file "filename.tmp"
// then rename over "filename".
// This way a password change atomically replaces the file.
func (cf *ConfFile) WriteFile() error {
	if err := cf.Validate(); err != nil {
		return err
	}
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
		// This can happen on network drives: FRITZ.NAS mounted on MacOS returns
		// "operation not supported": https://github.com/rfjakob/gocryptfs/issues/390
		tlog.Warn.Printf("Warning: fsync failed: %v", err)
		// Try sync instead
		syscall.Sync()
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
	cc := cryptocore.New(scryptHash, cryptocore.BackendGoGCM, IVLen, useHKDF)
	ce := contentenc.New(cc, 4096)
	return ce
}

// ContentEncryption tells us which content encryption algorithm is selected
func (cf *ConfFile) ContentEncryption() (algo cryptocore.AEADTypeEnum, err error) {
	if err := cf.Validate(); err != nil {
		return cryptocore.AEADTypeEnum{}, err
	}
	if cf.IsFeatureFlagSet(FlagXChaCha20Poly1305) {
		return cryptocore.BackendXChaCha20Poly1305, nil
	}
	if cf.IsFeatureFlagSet(FlagAESSIV) {
		return cryptocore.BackendAESSIV, nil
	}
	// If neither AES-SIV nor XChaCha are selected, we must be using AES-GCM
	return cryptocore.BackendGoGCM, nil
}
