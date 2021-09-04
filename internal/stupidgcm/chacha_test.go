// +build !without_openssl

package stupidgcm

import (
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestStupidChacha20poly1305(t *testing.T) {
	key := randBytes(32)
	c := NewChacha20poly1305(key)
	ref, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	testCiphers(t, c, ref)
}
