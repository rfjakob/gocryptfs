package main

import (
	"encoding/hex"
	"os"
	"strings"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// printMasterKey - remind the user that he should store the master key in
// a safe place
func printMasterKey(key []byte) {
	h := hex.EncodeToString(key)
	var hChunked string

	// Try to make it less scary by splitting it up in chunks
	for i := 0; i < len(h); i += 8 {
		hChunked += h[i : i+8]
		if i < 52 {
			hChunked += "-"
		}
		if i == 24 {
			hChunked += "\n    "
		}
	}

	tlog.Info.Printf(`
Your master key is:

    %s

If the gocryptfs.conf file becomes corrupted or you ever forget your password,
there is only one hope for recovery: The master key. Print it to a piece of
paper and store it in a drawer.

`, tlog.ColorGrey+hChunked+tlog.ColorReset)
}

// parseMasterKey - Parse a hex-encoded master key that was passed on the command line
// Calls os.Exit on failure
func parseMasterKey(masterkey string) []byte {
	masterkey = strings.Replace(masterkey, "-", "", -1)
	key, err := hex.DecodeString(masterkey)
	if err != nil {
		tlog.Fatal.Printf("Could not parse master key: %v\n", err)
		os.Exit(1)
	}
	if len(key) != cryptocore.KeyLen {
		tlog.Fatal.Printf("Master key has length %d but we require length %d\n", len(key), cryptocore.KeyLen)
		os.Exit(1)
	}
	return key
}
