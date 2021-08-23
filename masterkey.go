package main

import (
	"encoding/hex"
	"os"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/readpassword"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// unhexMasterKey - Convert a hex-encoded master key to binary.
// Calls os.Exit on failure.
func unhexMasterKey(masterkey string, fromStdin bool) []byte {
	masterkey = strings.Replace(masterkey, "-", "", -1)
	key, err := hex.DecodeString(masterkey)
	if err != nil {
		tlog.Fatal.Printf("Could not parse master key: %v", err)
		os.Exit(exitcodes.MasterKey)
	}
	if len(key) != cryptocore.KeyLen {
		tlog.Fatal.Printf("Master key has length %d but we require length %d", len(key), cryptocore.KeyLen)
		os.Exit(exitcodes.MasterKey)
	}
	tlog.Info.Printf("Using explicit master key.")
	if !fromStdin {
		tlog.Info.Printf(tlog.ColorYellow +
			"THE MASTER KEY IS VISIBLE VIA \"ps ax\" AND MAY BE STORED IN YOUR SHELL HISTORY!\n" +
			"ONLY USE THIS MODE FOR EMERGENCIES" + tlog.ColorReset)
	}
	return key
}

// handleArgsMasterkey looks at `args.masterkey` and `args.zerokey`, gets the
// masterkey from the source the user wanted (string on the command line, stdin, all-zero),
// and returns it in binary. Returns nil if no masterkey source was specified.
func handleArgsMasterkey(args *argContainer) (masterkey []byte) {
	// "-masterkey=stdin"
	if args.masterkey == "stdin" {
		in := string(readpassword.Once(nil, nil, "Masterkey"))
		return unhexMasterKey(in, true)
	}
	// "-masterkey=941a6029-3adc6a1c-..."
	if args.masterkey != "" {
		return unhexMasterKey(args.masterkey, false)
	}
	// "-zerokey"
	if args.zerokey {
		tlog.Info.Printf("Using all-zero dummy master key.")
		tlog.Info.Printf(tlog.ColorYellow +
			"ZEROKEY MODE PROVIDES NO SECURITY AT ALL AND SHOULD ONLY BE USED FOR TESTING." +
			tlog.ColorReset)
		return make([]byte, cryptocore.KeyLen)
	}
	// No master key source specified on the command line. Caller must parse
	// the config file.
	return nil
}
