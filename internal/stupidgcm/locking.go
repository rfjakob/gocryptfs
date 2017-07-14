// +build !without_openssl

package stupidgcm

// In general, OpenSSL is only threadsafe if you provide a locking function
// through CRYPTO_set_locking_callback. However, the GCM operations that
// stupidgcm uses never call that function. Additionally, the manual locking
// has been removed completely in openssl 1.1.0.

/*
#include <openssl/crypto.h>
#include <stdio.h>

static void dummy_callback(int mode, int n, const char *file, int line) {
	printf("stupidgcm: thread locking is not implemented and should not be "
		"needed. Please upgrade openssl.\n");
	// panic
	__builtin_trap();
}
static void set_dummy_callback() {
	CRYPTO_set_locking_callback(dummy_callback);
}
*/
import "C"

func init() {
	C.set_dummy_callback()
}
