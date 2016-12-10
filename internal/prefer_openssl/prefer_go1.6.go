// +build go1.6,amd64
// go1.6+ AND amd64

package prefer_openssl

import (
	"runtime"

	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
)

// PreferOpenSSL tells us if OpenSSL is faster than Go GCM on this machine.
// Go GCM is faster when the CPU has AES instructions and Go is v1.6 or higher
// on amd64.
//
// See https://github.com/rfjakob/gocryptfs/issues/23#issuecomment-218286502
// for benchmarks.
func PreferOpenSSL() bool {
	if stupidgcm.BuiltWithoutOpenssl {
		return false
	}
	if runtime.GOOS == "darwin" {
		// OSX does not have /proc/cpuinfo, let's just assume the CPU has AES
		// acceleration. Virtually all Macs that are running today have it I
		// guess?
		return false
	}
	return filePreferOpenSSL("/proc/cpuinfo")
}
