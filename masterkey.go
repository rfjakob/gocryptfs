package main

import (
	"encoding/hex"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// printMasterKey - remind the user that he should store the master key in
// a safe place
func printMasterKey(key []byte) {
	if !terminal.IsTerminal(int(os.Stdout.Fd())) {
		// We don't want the master key to end up in a log file
		tlog.Info.Printf("Not running on a terminal, suppressing master key display\n")
		return
	}
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
paper and store it in a drawer. Use "-q" to suppress this message.

`, tlog.ColorGrey+hChunked+tlog.ColorReset)
}

// parseMasterKey - Parse a hex-encoded master key that was passed on the command line
// Calls os.Exit on failure
func parseMasterKey(masterkey string, fromStdin bool) []byte {
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

// getMasterKey looks at "args" to determine where the master key should come
// from (-masterkey=a-b-c-d or stdin or from the config file).
// If it comes from the config file, the user is prompted for the password
// and a ConfFile instance is returned.
// Calls os.Exit on failure.
func getMasterKey(args *argContainer) (masterkey []byte, confFile *configfile.ConfFile) {
	masterkeyFromStdin := false
	// "-masterkey=stdin"
	if args.masterkey == "stdin" {
		args.masterkey = string(readpassword.Once("", "Masterkey"))
		masterkeyFromStdin = true
	}
	// "-masterkey=941a6029-3adc6a1c-..."
	if args.masterkey != "" {
		return parseMasterKey(args.masterkey, masterkeyFromStdin), nil
	}
	// "-zerokey"
	if args.zerokey {
		tlog.Info.Printf("Using all-zero dummy master key.")
		tlog.Info.Printf(tlog.ColorYellow +
			"ZEROKEY MODE PROVIDES NO SECURITY AT ALL AND SHOULD ONLY BE USED FOR TESTING." +
			tlog.ColorReset)
		return make([]byte, cryptocore.KeyLen), nil
	}
	var err error
	// Load master key from config file (normal operation).
	// Prompts the user for the password.
	masterkey, confFile, err = loadConfig(args)
	if err != nil {
		if args._ctlsockFd != nil {
			// Close the socket file (which also deletes it)
			args._ctlsockFd.Close()
		}
		exitcodes.Exit(err)
	}
	if !args.trezor {
		readpassword.CheckTrailingGarbage()
	}
	if !args.fsck {
		// We only want to print the masterkey message on a normal mount.
		printMasterKey(masterkey)
	}
	return masterkey, confFile
}
