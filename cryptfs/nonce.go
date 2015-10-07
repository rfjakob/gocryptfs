package cryptfs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Get "n" random bytes from /dev/urandom or panic
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

var gcmNonce nonce96

type nonce96 struct {
	lastNonce []byte
}

// Get a random 96 bit nonce
func (n *nonce96) Get() []byte {
	nonce := RandBytes(12)
	Debug.Printf("nonce96.Get(): %s\n", hex.EncodeToString(nonce))
	if bytes.Equal(nonce, n.lastNonce) {
		m := fmt.Sprintf("Got the same nonce twice: %s. This should never happen!", hex.EncodeToString(nonce))
		panic(m)
	}
	n.lastNonce = nonce
	return nonce
}
