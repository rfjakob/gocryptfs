package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

// info pretty-prints the contents of the config file at "filename" for human
// consumption, stripping out sensitive data.
// This is called when you pass the "-info" option.
func info(filename string) {
	cf, err := configfile.Load(filename)
	if err != nil {
		fmt.Printf("Loading config file failed: %v\n", err)
		os.Exit(exitcodes.LoadConf)
	}
	s := cf.ScryptObject
	algo, _ := cf.ContentEncryption()
	// Pretty-print
	fmt.Printf("Creator:           %s\n", cf.Creator)
	fmt.Printf("FeatureFlags:      %s\n", strings.Join(cf.FeatureFlags, " "))
	fmt.Printf("EncryptedKey:      %dB\n", len(cf.EncryptedKey))
	fmt.Printf("ScryptObject:      Salt=%dB N=%d R=%d P=%d KeyLen=%d\n",
		len(s.Salt), s.N, s.R, s.P, s.KeyLen)
	fmt.Printf("contentEncryption: %s\n", algo.Algo) // lowercase because not in JSON
}
