package readpassword

import (
	"os"

	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/tlog"

	"github.com/xaionaro-go/cryptoWallet"
	"github.com/xaionaro-go/cryptoWallet/vendors"
)

// It's required initial values to be constant to get the resulting key to
// be deterministic (see the comment above and within function "Trezor()").
// This values could be just a bunch of zeros, but it seems to be a little
// degenerate case that may add risks, so a string "gocryptfs.trezor" was
// used. The key should be a multiple of 16 bytes, but we use 32 bytes
// (256bits) key.
const (
	trezorDummyKey          = "gocryptfs.trezorgocryptfs.trezor"
	trezorNonce             = "" // the "nonce" is optional and has no use in here
	trezorKeyName           = "gocryptfs"
	trezorKeyDerivationPath = `m/10019'/0'/0'/0'`
)

func trezorGetPin(title, description, ok, cancel string) ([]byte, error) {
	return Once("", title), nil
}
func trezorGetConfirm(title, description, ok, cancel string) (bool, error) {
	return false, nil // do not retry on connection failure
}

// Trezor reads 32 deterministically derived bytes from a
// SatoshiLabs Trezor USB security module.
// The bytes are pseudorandom binary data and may contain null bytes.
// This function either succeeds and returns 32 bytes or calls os.Exit to end
// the application.
func Trezor() []byte {
	// Find all trezor devices
	trezors := cryptoWallet.Find(cryptoWallet.Filter{
		VendorID:   &[]uint16{vendors.GetVendorID("satoshilabs")}[0],
		ProductIDs: []uint16{1 /* Trezor One */},
	})

	// ATM, we require to one and only one trezor device to be connected.
	// The support of multiple trezor devices is not implemented, yet.
	if len(trezors) == 0 {
		tlog.Fatal.Printf("Trezor device is not found. Check the connection.")
		os.Exit(exitcodes.TrezorError)
	}
	if len(trezors) > 1 {
		tlog.Fatal.Printf("It's more than one Trezor device connected. This case is not implemented, yet. The number of currently connected devices: %v.", len(trezors))
		os.Exit(exitcodes.TrezorError)
	}

	// Using the first found device
	trezor := trezors[0]

	// Trezor may ask for PIN or Passphrase. Setting the handler for this case.
	trezor.SetGetPinFunc(trezorGetPin)

	// In some cases (like lost connection to the Trezor device and cannot
	// reconnect) it's required to get a confirmation from the user to
	// retry to reconnect. Setting the handler for this case.
	trezor.SetGetConfirmFunc(trezorGetConfirm)

	// To generate a deterministic key we trying to decrypt our
	// predefined constant key using the Trezor device. The resulting key
	// will depend on next variables:
	// * the Trezor master key;
	// * the passphrase (passed to the Trezor).
	//
	// The right key will be received only if both values (mentioned
	// above) are correct.
	//
	// Note:
	// Also the resulting key depends on this values (that we defined as
	// constants above):
	// * the key derivation path;
	// * the "encrypted" key;
	// * the nonce;
	// * the key name.
	key, err := trezor.DecryptKey(trezorKeyDerivationPath, []byte(trezorDummyKey), []byte(trezorNonce), trezorKeyName)
	if err != nil {
		tlog.Fatal.Printf("Cannot get the key from the Trezor device. Error description:\n\t%v", err.Error())
		os.Exit(exitcodes.TrezorError)
	}

	// Everything ok
	return key
}
