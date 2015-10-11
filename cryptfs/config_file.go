package cryptfs

import (
	"encoding/json"
	"io/ioutil"
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
}

// CreateConfFile - create a new config with a random key encrypted with
// "password" and write it to "filename"
func CreateConfFile(filename string, password string) error {
	var cf ConfFile
	cf.filename = filename

	// Generate new random master key
	key := RandBytes(KEY_LEN)

	// Encrypt it using the password
	cf.EncryptKey(key, password)

	// Write file to disk
	err := cf.WriteFile()

	return err
}

// LoadConfFile - read config file from disk and decrypt the
// contained key using password
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

	// Generate derived key from password
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Unlock master key using password-based key
	// We use stock go GCM instead of OpenSSL here as speed is not important
	// and we get better error messages
	cfs := NewCryptFS(scryptHash, false)
	key, err := cfs.DecryptBlock(cf.EncryptedKey, 0)
	if err != nil {
		Warn.Printf("failed to unlock master key: %s\n", err.Error())
		Warn.Printf("Password incorrect.\n")
		return nil, nil, err
	}

	return key, &cf, nil
}

// EncryptKey - encrypt "key" using an scrypt hash generated from "password"
// and store it in cf.EncryptedKey
func (cf *ConfFile) EncryptKey(key []byte, password string) {
	// Generate derived key from password
	cf.ScryptObject = NewScryptKdf()
	scryptHash := cf.ScryptObject.DeriveKey(password)

	// Lock master key using password-based key
	cfs := NewCryptFS(scryptHash, false)
	cf.EncryptedKey = cfs.EncryptBlock(key, 0)
}

// WriteFile - write out config in JSON format to file "filename.tmp"
// then rename over "filename"
func (cf *ConfFile) WriteFile() error {
	tmp := cf.filename + ".tmp"
	fd, err := os.Create(tmp)
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
