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
// degenerate case that may add risks, so random values were used.
//
// This values were generated using command:
//   dd if=/dev/random of=/dev/stdout bs=48 count=1 2>/dev/null | hexdump -e '8/1 "0x%02x, " "\n"'
var (
	TREZOR_DUMMYKEY = []byte{
		0xfc, 0x3b, 0xe3, 0xa6, 0xe6, 0x61, 0x32, 0xbc,
		0x95, 0x86, 0x79, 0x06, 0x70, 0xf9, 0x7c, 0x0a,
		0xab, 0x05, 0x3b, 0x12, 0xff, 0x4e, 0xa8, 0x8b,
		0x5b, 0x58, 0x0a, 0x8e, 0x42, 0xcf, 0x5e, 0x20,
	}
	TREZOR_NONCE = []byte{
		0xc9, 0xf1, 0x6d, 0xab, 0xba, 0x16, 0x68, 0xc9,
		0xcc, 0xb6, 0xb2, 0xcd, 0xbc, 0x4a, 0xb6, 0xcb,
	}
	TREZOR_KEY_NAME            = "gocryptfs"
	TREZOR_KEY_DERIVATION_PATH = `m/10019'/0'/0'/0'`
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

	// To generate a deterministic the key we trying to decrypt our
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
	key, err := trezor.DecryptKey(TREZOR_KEY_DERIVATION_PATH, TREZOR_DUMMYKEY, TREZOR_NONCE, TREZOR_KEY_NAME)
	if err != nil {
		tlog.Fatal.Printf("Cannot get the key from the Trezor device. Error description:\n\t%v", err.Error())
		os.Exit(exitcodes.TrezorError)
	}

	// Everything ok
	return key
}
