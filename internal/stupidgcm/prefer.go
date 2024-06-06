package stupidgcm

import (
	"runtime"
)

// PreferOpenSSLAES256GCM tells us if OpenSSL AES-256-GCM is faster than Go stdlib
// on this machine.
//
// Go GCM is only faster if the CPU either:
//
//  1. Is X86_64 && has AES instructions && Go is v1.6  or higher
//  2. Is ARM64  && has AES instructions && Go is v1.11 or higher
//     (commit https://github.com/golang/go/commit/4f1f503373cda7160392be94e3849b0c9b9ebbda)
//
// See https://github.com/rfjakob/gocryptfs/wiki/CPU-Benchmarks
// for benchmarks.
func PreferOpenSSLAES256GCM() bool {
	if BuiltWithoutOpenssl {
		return false
	}
	// If the CPU has AES acceleration, Go stdlib is faster
	if HasAESGCMHardwareSupport() {
		return false
	}
	// Otherwise OpenSSL is probably faster
	return true
}

// PreferOpenSSLXchacha20poly1305 returns true if OpenSSL Xchacha20poly1305 is
// faster than Go stdlib on this machine.
func PreferOpenSSLXchacha20poly1305() bool {
	if BuiltWithoutOpenssl {
		return false
	}
	// Go x/crypto has optimized assembly for amd64:
	// https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_amd64.s
	if runtime.GOARCH == "amd64" {
		return false
	}
	// On arm64 and arm, OpenSSL is faster. Probably everywhere else too.
	return true
}

// HasAESGCMHardwareSupport tells you if the CPU we are running has AES-GCM
// acceleration that is usable by the Go crypto library.
func HasAESGCMHardwareSupport() bool {
	if hasAESGCMHardwareSupport {
		return true
	}

	// On the Apple M1, the CPU has AES acceleration, despite cpu.ARM64.HasAES
	// reading false: https://github.com/rfjakob/gocryptfs/issues/556#issuecomment-848079309
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return true
	}
	return false
}
