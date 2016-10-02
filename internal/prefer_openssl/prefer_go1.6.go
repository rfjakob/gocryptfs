// +build go1.6,amd64
// go1.6+ AND amd64

package prefer_openssl

// PreferOpenSSL tells us if OpenSSL is faster than Go GCM on this machine.
// Go GCM is faster when the CPU has AES instructions and Go is v1.6 or higher
// on amd64.
//
// See https://github.com/rfjakob/gocryptfs/issues/23#issuecomment-218286502
// for benchmarks.
func PreferOpenSSL() bool {
	return filePreferOpenSSL("/proc/cpuinfo")
}
