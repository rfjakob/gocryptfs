// Package trezor implements master key encryption mechanism
// using open(hardware) device "Trezor One"
package trezor

import (
	"encoding/hex"
	"log"

	"github.com/conejoninja/tesoro"
	"github.com/conejoninja/tesoro/pb/messages"
	"github.com/xaionaro-go/pinentry"
	"github.com/zserge/hid"
)

const (
	TrezorPassword = "trezor"
)

type trezor struct {
	tesoro.Client
	pinentry pinentry.PinentryClient
	hid.Device
}

func New() *trezor {
	pinentryClient, _ := pinentry.NewPinentryClient()
	trezorInstance := trezor{
		pinentry: pinentryClient,
	}
	trezorInstance.Reconnect()
	return &trezorInstance
}

type trezorCipher struct {
	*trezor
	keyName string
}

func (trezor *trezor) call(msg []byte) (string, uint16) {
	result, msgType := trezor.Client.Call(msg)

	switch messages.MessageType(msgType) {
	case messages.MessageType_MessageType_PinMatrixRequest:

		trezor.pinentry.SetPrompt("PIN")
		trezor.pinentry.SetDesc("")
		trezor.pinentry.SetOK("Confirm")
		trezor.pinentry.SetCancel("Cancel")
		pin, err := trezor.pinentry.GetPin()
		if err != nil {
			log.Print("Error", err)
		}
		result, msgType = trezor.call(trezor.Client.PinMatrixAck(string(pin)))

	case messages.MessageType_MessageType_ButtonRequest:

		result, msgType = trezor.call(trezor.Client.ButtonAck())

	case messages.MessageType_MessageType_PassphraseRequest:

		trezor.pinentry.SetPrompt("Passphrase")
		trezor.pinentry.SetDesc("")
		trezor.pinentry.SetOK("Confirm")
		trezor.pinentry.SetCancel("Cancel")
		passphrase, err := trezor.pinentry.GetPin()
		if err != nil {
			log.Print("Error", err)
		}
		result, msgType = trezor.call(trezor.Client.PassphraseAck(string(passphrase)))

	case messages.MessageType_MessageType_WordRequest:

		trezor.pinentry.SetPrompt("Word")
		trezor.pinentry.SetDesc("")
		trezor.pinentry.SetOK("OK")
		trezor.pinentry.SetCancel("Cancel")
		word, err := trezor.pinentry.GetPin()
		if err != nil {
			log.Print("Error", err)
		}
		result, msgType = trezor.call(trezor.Client.WordAck(string(word)))

	}

	return result, msgType
}

func (trezor *trezor) Ping() bool {
	if trezor.Device == nil {
		return false
	}
	if _, err := trezor.Device.HIDReport(); err != nil {
		return false
	}
	str, _ := trezor.Client.Call(trezor.Client.Ping("gocryptfs", false, false, false))
	return str == "gocryptfs"
}

func (trezor *trezor) CheckTrezorConnection() {
	if trezor.Ping() {
		return
	}

	trezor.Reconnect()
}

// See https://github.com/satoshilabs/slips/blob/master/slip-0011.md
func (trezor *trezor) CipherKeyValue(isToEncrypt bool, keyName string, data, iv []byte, askOnEncode, askOnDecode bool) ([]byte, messages.MessageType) {
	path := `m/71'/a6'/3'/45'/96'`
	result, msgType := trezor.call(trezor.Client.CipherKeyValue(isToEncrypt, keyName, data, tesoro.StringToBIP32Path(path), iv, askOnEncode, askOnDecode))
	return []byte(result), messages.MessageType(msgType)
}

func (trezor *trezor) EncryptKey(decryptedKey []byte, nonce []byte, trezorKeyname string) []byte {
	// note: decryptedKey length should be aligned to 16 bytes

	trezor.CheckTrezorConnection()

	encryptedKey, _ := trezor.CipherKeyValue(true, trezorKeyname, decryptedKey, nonce, false, true)

	return encryptedKey
}

func (trezor *trezor) DecryptKey(encryptedKey []byte, nonce []byte, trezorKeyname string) []byte {
	// note: encryptedKey length should be aligned to 16 bytes

	trezor.CheckTrezorConnection()

	// library "tesoro" requires hex-ed value for decryption
	encryptedKeyhexValue := hex.EncodeToString(encryptedKey)
	if len(encryptedKeyhexValue)%2 != 0 {
		log.Panic("len(hexValue)%2 != 0")
	}
	for len(encryptedKeyhexValue)%32 != 0 {
		encryptedKeyhexValue += "00"
	}

	decryptedKey, msgType := trezor.CipherKeyValue(false, trezorKeyname, []byte(encryptedKeyhexValue), nonce, false, true)

	if msgType == messages.MessageType_MessageType_Failure {
		log.Panicf("trezor: %v", string(decryptedKey)) // if an error occurs then the error description is returned into "decryptedKey" as a string
	}

	return decryptedKey
}
