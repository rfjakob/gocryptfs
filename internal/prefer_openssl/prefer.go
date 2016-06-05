package prefer_openssl

import (
	"io/ioutil"
	"regexp"

	"github.com/rfjakob/gocryptfs/internal/toggledlog"
)

// filePreferOpenSSL tells us if OpenSSL is faster than Go GCM on this machine.
// Go GCM is fastern when the CPU has AES instructions and Go is v1.6 or higher.
//
// See https://github.com/rfjakob/gocryptfs/issues/23#issuecomment-218286502
// for benchmarks.
//
// filePreferOpenSSL takes an explicit filename so it can be tested with saved
// cpuinfo files instead of /proc/cpuinfo.
func filePreferOpenSSL(file string) bool {
	ci, err := ioutil.ReadFile(file)
	if err != nil {
		toggledlog.Warn.Println(err)
		return true
	}
	haveAes, err := regexp.Match(`(?m)^flags.*\baes\b`, ci)
	if err != nil {
		toggledlog.Warn.Println(err)
		return true
	}
	return !haveAes
}
