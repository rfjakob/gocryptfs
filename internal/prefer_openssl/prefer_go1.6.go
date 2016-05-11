// +build go1.6
// = go 1.6 or higher

package prefer_openssl

// PreferOpenSSL tells us if OpenSSL is faster than Go GCM on this machine.
// Go GCM is fastern when the CPU has AES instructions and Go is v1.6 or higher.
//
// See https://github.com/rfjakob/gocryptfs/issues/23#issuecomment-218286502
// for benchmarks.
func PreferOpenSSL() bool {
	return filePreferOpenSSL("/proc/cpuinfo")
}
