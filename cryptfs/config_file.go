package cryptfs

import (
	"errors"
	"io/ioutil"
	"encoding/json"
)
import "os"

const (
	// Changing this string breaks backward compatability
	testBlockData = "gocryptfs test block"

	// The dot "." is not used in base64url (RFC4648), hence
	// we can never clash with an encrypted file.
	ConfDefaultName = "gocryptfs.conf"
)

type confFile struct {
	// File the config is saved in. Lowercase => not exported to JSON.
	filename string
	// Unencrypted AES key
	Key [16]byte
	// GCM ciphertext with auth tag to verify the key is correct
	TestBlock []byte
}

// CreateConfFile - create a new config file with "key" and write to "filename"
func CreateConfFile(filename string, key [16]byte) error {
	var cf confFile
	cf.filename = filename
	cf.Key = key

	// Generate test block
	cfs := NewCryptFS(cf.Key, false)
	cf.TestBlock = cfs.EncryptBlock([]byte(testBlockData))

	// Write file to disk
	err := cf.WriteFile()

	return err
}

// LoadConfFile - read config file from disk and verify the key using the
// embedded TestBlock
func LoadConfFile(filename string) (*confFile, error) {
	// Read from disk
	js, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cf confFile
	err = json.Unmarshal(js, &cf)
	if err != nil {
		return nil, err
	}
	cf.filename = filename

	// Try to decrypt the test block to see if the key is correct
	//
	// Speed does not matter here. Use built-in crypto.
	cfs := NewCryptFS(cf.Key, false)
	d, err := cfs.DecryptBlock(cf.TestBlock)
	if err != nil {
		return nil, err
	}
	ds := string(d)
	if ds != testBlockData {
		return nil, errors.New("Invalid test block content: " + ds)
	}
	return &cf, nil
}

// WriteFile - write out config in JSON format to file "filename.tmp"
// then rename over "filename"
func (cf *confFile) WriteFile() error {
	tmp := cf.filename + ".tmp"
	fd, err := os.Create(tmp)
	if err != nil {
		return err
	}
	js, err := json.Marshal(cf)
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
