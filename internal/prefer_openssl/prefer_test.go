package prefer_openssl

import (
	"testing"
)

func TestCurrentCPU(t *testing.T) {
	t.Logf("PreferOpenSSL=%v", PreferOpenSSL())
}

// Has AES instructions
func TestXeonE312xx(t *testing.T) {
	if filePreferOpenSSL("cpuinfo.xeon_e312xx.txt") == true {
		t.Fail()
	}
}

// Pentium G do not have AES instructions
func TestPentiumG630(t *testing.T) {
	if filePreferOpenSSL("cpuinfo.pentium_g630.txt") == false {
		t.Fail()
	}
}
