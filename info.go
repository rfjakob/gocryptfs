package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// info pretty-prints the contents of the config file at "filename" for human
// consumption, stripping out sensitive data.
// This is called when you pass the "-info" option.
func info(filename string) {
	// Read from disk
	js, err := ioutil.ReadFile(filename)
	if err != nil {
		tlog.Fatal.Printf("info: ReadFile: %#v\n", err)
		os.Exit(exitcodes.LoadConf)
	}
	// Unmarshal
	var cf configfile.ConfFile
	err = json.Unmarshal(js, &cf)
	if err != nil {
		tlog.Fatal.Printf("Failed to unmarshal config file")
		os.Exit(exitcodes.LoadConf)
	}
	if cf.Version != contentenc.CurrentVersion {
		tlog.Fatal.Printf("Unsupported on-disk format %d", cf.Version)
		os.Exit(exitcodes.LoadConf)
	}
	// Pretty-print
	fmt.Printf("Creator:      %s\n", cf.Creator)
	fmt.Printf("FeatureFlags: %s\n", strings.Join(cf.FeatureFlags, " "))
	fmt.Printf("EncryptedKey: %dB\n", len(cf.EncryptedKey))
	s := cf.ScryptObject
	fmt.Printf("ScryptObject: Salt=%dB N=%d R=%d P=%d KeyLen=%d\n",
		len(s.Salt), s.N, s.R, s.P, s.KeyLen)
	os.Exit(0)
}
