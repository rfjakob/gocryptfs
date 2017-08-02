// +build !go1.5

// Cause an early compile error on Go 1.4 an lower. We need Go 1.5 for a number
// of reasons, among them NewGCMWithNonceSize and RawURLEncoding.
"You need Go 1.5 or higher to compile gocryptfs!"
