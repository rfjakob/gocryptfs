package cryptocore

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// RandBytes gets "n" random bytes from /dev/urandom or panics
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// RandUint64 returns a secure random uint64
func RandUint64() uint64 {
	b := RandBytes(8)
	return binary.BigEndian.Uint64(b)
}

type nonceGenerator struct {
	lastNonce []byte
	nonceLen  int // bytes
}

// Get a random "nonceLen"-byte nonce
func (n *nonceGenerator) Get() []byte {
	nonce := RandBytes(n.nonceLen)
	tlog.Debug.Printf("nonceGenerator.Get(): %s\n", hex.EncodeToString(nonce))
	if bytes.Equal(nonce, n.lastNonce) {
		m := fmt.Sprintf("Got the same nonce twice: %s. This should never happen!", hex.EncodeToString(nonce))
		panic(m)
	}
	n.lastNonce = nonce
	return nonce
}
