// +build !without_openssl

package stupidgcm

import (
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestStupidXchacha20poly1305(t *testing.T) {
	key := randBytes(32)
	c := NewXchacha20poly1305(key)
	ref, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}

	testCiphers(t, c, ref)
}
