package stupidgcm

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// PreferOpenSSLAES256GCM tells us if OpenSSL AES-256-GCM is faster than Go stdlib
// on this machine.
//
// Go GCM is only faster if the CPU either:
//
// 1) Is X86_64 && has AES instructions && Go is v1.6  or higher
// 2) Is ARM64  && has AES instructions && Go is v1.11 or higher
//    (commit https://github.com/golang/go/commit/4f1f503373cda7160392be94e3849b0c9b9ebbda)
//
// See https://github.com/rfjakob/gocryptfs/wiki/CPU-Benchmarks
// for benchmarks.
func PreferOpenSSLAES256GCM() bool {
	if BuiltWithoutOpenssl {
		return false
	}
	// Safe to call on other architectures - will just read false.
	if cpu.X86.HasAES || cpu.ARM64.HasAES {
		// Go stdlib is probably faster
		return false
	}
	// On the Apple M1, Go stdlib is faster than OpenSSL, despite cpu.ARM64.HasAES
	// reading false: https://github.com/rfjakob/gocryptfs/issues/556#issuecomment-848079309
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return false
	}
	// OpenSSL is probably faster
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
	// On arm64 and arm, OpenSSL is faster. Probably everwhere else too.
	return true
}
