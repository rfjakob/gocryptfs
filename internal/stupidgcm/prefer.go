package stupidgcm

import (
	"golang.org/x/sys/cpu"
)

// PreferOpenSSL tells us if OpenSSL is faster than Go GCM on this machine.
//
// Go GCM is only faster if the CPU:
//
// 1) Is X86
// 2) Has AES instructions
// 3) Go is v1.6 or higher
//
// See https://github.com/rfjakob/gocryptfs/wiki/CPU-Benchmarks
// for benchmarks.
func PreferOpenSSL() bool {
	if BuiltWithoutOpenssl {
		return false
	}
	// Safe to call on other architectures - will just read false.
	if cpu.X86.HasAES {
		return false
	}
	return true
}
