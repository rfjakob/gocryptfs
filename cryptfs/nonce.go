package cryptfs

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync"
)

type nonce96 struct {
	lock   sync.Mutex
	high32 uint32
	low64  uint64
	ready  int
}

var gcmNonce nonce96

// Get "n" random bytes from /dev/urandom or panic
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic("Could not get random bytes for nonce")
	}
	return b
}

func (n *nonce96) init() {
	b := RandBytes(8)
	n.low64 = binary.BigEndian.Uint64(b)
	b = RandBytes(4)
	n.high32 = binary.BigEndian.Uint32(b)
	n.ready = 1
	return
}

func (n *nonce96) Get() []byte {
	n.lock.Lock()
	if n.ready == 0 {
		n.init()
	}
	n.low64++
	if n.low64 == 0 {
		// Counter has wrapped
		n.high32++
	}
	r := make([]byte, 12)
	binary.BigEndian.PutUint32(r[0:4], n.high32)
	binary.BigEndian.PutUint64(r[4:12], n.low64)
	n.lock.Unlock()

	Debug.Printf("nonce96.Get(): %s\n", hex.EncodeToString(r))

	return r
}
