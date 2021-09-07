// +build !without_openssl

package stupidgcm

import (
	"fmt"
	"log"
)

/*
#include "openssl_aead.h"
#cgo pkg-config: libcrypto
*/
import "C"

func openSSLSeal(a *stupidAEADCommon, dst, iv, in, authData []byte) []byte {
	if a.Wiped() {
		log.Panic("BUG: tried to use wiped key")
	}
	if len(iv) != a.NonceSize() {
		log.Panicf("Only %d-byte IVs are supported, you passed %d bytes", a.NonceSize(), len(iv))
	}

	// If the "dst" slice is large enough we can use it as our output buffer
	outLen := len(in) + tagLen
	var buf []byte
	inplace := false
	if cap(dst)-len(dst) >= outLen {
		inplace = true
		buf = dst[len(dst) : len(dst)+outLen]
	} else {
		buf = make([]byte, outLen)
	}

	res := int(C.openssl_aead_seal(a.openSSLEVPCipher,
		slicePointerOrNull(in),
		C.int(len(in)),
		(*C.uchar)(&authData[0]),
		C.int(len(authData)),
		(*C.uchar)(&a.key[0]),
		C.int(len(a.key)),
		(*C.uchar)(&iv[0]),
		C.int(len(iv)),
		(*C.uchar)(&buf[0]),
		C.int(len(buf))))

	if res != outLen {
		log.Panicf("expected length %d, got %d", outLen, res)
	}

	if inplace {
		return dst[:len(dst)+outLen]
	}
	return append(dst, buf...)
}

func openSSLOpen(a *stupidAEADCommon, dst, iv, in, authData []byte) ([]byte, error) {
	if a.Wiped() {
		log.Panic("BUG: tried to use wiped key")
	}
	if len(iv) != a.NonceSize() {
		log.Panicf("Only %d-byte IVs are supported, you passed %d bytes", a.NonceSize(), len(iv))
	}
	if len(in) < tagLen {
		return nil, fmt.Errorf("stupidChacha20poly1305: input data too short (%d bytes)", len(in))
	}

	// If the "dst" slice is large enough we can use it as our output buffer
	outLen := len(in) - tagLen
	var buf []byte
	inplace := false
	if cap(dst)-len(dst) >= outLen {
		inplace = true
		buf = dst[len(dst) : len(dst)+outLen]
	} else {
		buf = make([]byte, len(in)-tagLen)
	}

	ciphertext := in[:len(in)-tagLen]
	tag := in[len(in)-tagLen:]

	res := int(C.openssl_aead_open(a.openSSLEVPCipher,
		slicePointerOrNull(ciphertext),
		C.int(len(ciphertext)),
		(*C.uchar)(&authData[0]),
		C.int(len(authData)),
		(*C.uchar)(&tag[0]),
		C.int(len(tag)),
		(*C.uchar)(&a.key[0]),
		C.int(len(a.key)),
		(*C.uchar)(&iv[0]),
		C.int(len(iv)),
		slicePointerOrNull(buf),
		C.int(len(buf))))

	if res < 0 {
		return nil, ErrAuth
	}
	if res != outLen {
		log.Panicf("unexpected length %d", res)
	}

	if inplace {
		return dst[:len(dst)+outLen], nil
	}
	return append(dst, buf...), nil
}

// slicePointerOrNull returns a C pointer to the beginning of the byte slice,
// or NULL if the byte slice is empty. This is useful for slices that can be
// empty, otherwise you can directly use "(*C.uchar)(&s[0])".
func slicePointerOrNull(s []byte) (ptr *C.uchar) {
	if len(s) == 0 {
		return
	}
	return (*C.uchar)(&s[0])
}

// This functions exists to benchmark the C call overhead from Go.
// See BenchmarkCCall for resuts.
func noopCFunction() {
	C.noop_c_function()
}
