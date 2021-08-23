package stupidgcm

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// PreferOpenSSL tells us if OpenSSL is faster than Go GCM on this machine.
//
// Go GCM is only faster if the CPU either:
//
// 1) Is X86_64 && has AES instructions && Go is v1.6  or higher
// 2) Is ARM64  && has AES instructions && Go is v1.11 or higher
//    (commit https://github.com/golang/go/commit/4f1f503373cda7160392be94e3849b0c9b9ebbda)
//
// See https://github.com/rfjakob/gocryptfs/v2/wiki/CPU-Benchmarks
// for benchmarks.
func PreferOpenSSL() bool {
	if BuiltWithoutOpenssl {
		return false
	}
	// Safe to call on other architectures - will just read false.
	if cpu.X86.HasAES || cpu.ARM64.HasAES {
		// Go stdlib is probably faster
		return false
	}
	// On the Apple M1, Go stdlib is faster than OpenSSL, despite cpu.ARM64.HasAES
	// reading false: https://github.com/rfjakob/gocryptfs/v2/issues/556#issuecomment-848079309
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return false
	}
	// OpenSSL is probably faster
	return true
}
