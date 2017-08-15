// +build !go1.5

package main

// Cause an early compile error on Go 1.4 an lower. We need Go 1.5 for a number
// of reasons, among them NewGCMWithNonceSize, RawURLEncoding, runtime/trace.
import "You_need_Go_1.5_or_higher_to_compile_gocryptfs"
