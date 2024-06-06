package stupidgcm

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// ********
// Carbon-copied from Go Stdlib
// https://github.com/golang/go/blob/45967bb18e04fa6dc62c2786c87ce120443c64f6/src/crypto/tls/cipher_suites.go#L367
// ********

var (
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	// Keep in sync with crypto/aes/cipher_s390x.go.
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR &&
		(cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasAESGCMHardwareSupport = runtime.GOARCH == "amd64" && hasGCMAsmAMD64 ||
		runtime.GOARCH == "arm64" && hasGCMAsmARM64 ||
		runtime.GOARCH == "s390x" && hasGCMAsmS390X
)

// ********
// End carbon-copy
// ********
