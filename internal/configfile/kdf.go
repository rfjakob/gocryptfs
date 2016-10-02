package configfile

import (
	"log"
	"math"
	"os"

	"golang.org/x/crypto/scrypt"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// ScryptDefaultLogN is the default scrypt logN configuration parameter.
	// 1 << 16 uses 64MB of memory,
	// takes 4 seconds on my Atom Z3735F netbook
	ScryptDefaultLogN = 16
)

// ScryptKDF is an instance of the scrypt key deriviation function.
type ScryptKDF struct {
	Salt   []byte
	N      int
	R      int
	P      int
	KeyLen int
}

// NewScryptKDF returns a new instance of ScryptKDF.
func NewScryptKDF(logN int) ScryptKDF {
	var s ScryptKDF
	s.Salt = cryptocore.RandBytes(cryptocore.KeyLen)
	if logN <= 0 {
		s.N = 1 << ScryptDefaultLogN
	} else {
		if logN < 10 {
			tlog.Fatal.Println("Error: scryptn below 10 is too low to make sense. Aborting.")
			os.Exit(1)
		}
		s.N = 1 << uint32(logN)
	}
	s.R = 8 // Always 8
	s.P = 1 // Always 1
	s.KeyLen = cryptocore.KeyLen
	return s
}

// DeriveKey returns a new key from a supplied password.
func (s *ScryptKDF) DeriveKey(pw string) []byte {
	k, err := scrypt.Key([]byte(pw), s.Salt, s.N, s.R, s.P, s.KeyLen)
	if err != nil {
		log.Panicf("DeriveKey failed: %v", err)
	}
	return k
}

// LogN - N is saved as 2^LogN, but LogN is much easier to work with.
// This function gives you LogN = Log2(N).
func (s *ScryptKDF) LogN() int {
	return int(math.Log2(float64(s.N)) + 0.5)
}
