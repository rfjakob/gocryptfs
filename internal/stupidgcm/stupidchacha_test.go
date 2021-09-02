// +build !without_openssl

// We compare against Go's built-in GCM implementation. Since stupidgcm only
// supports 128-bit IVs and Go only supports that from 1.5 onward, we cannot
// run these tests on older Go versions.
package stupidgcm

import (
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestStupidChacha20poly1305(t *testing.T) {
	key := randBytes(32)
	c := newChacha20poly1305(key)
	ref, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	testCiphers(t, c, ref)
}
