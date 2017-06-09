package cryptocore

import (
	"crypto/rand"
	"encoding/binary"
	"log"
)

// RandBytes gets "n" random bytes from /dev/urandom or panics
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// RandUint64 returns a secure random uint64
func RandUint64() uint64 {
	b := RandBytes(8)
	return binary.BigEndian.Uint64(b)
}

type nonceGenerator struct {
	nonceLen int // bytes
}

// Get a random "nonceLen"-byte nonce
func (n *nonceGenerator) Get() []byte {
	return randPrefetcher.read(n.nonceLen)
}
