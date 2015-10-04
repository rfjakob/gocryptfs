package cryptfs

import (
	"fmt"
	"golang.org/x/crypto/scrypt"
)

const (
	// 1 << 16 uses 64MB of memory,
	// takes 4 seconds on my Atom Z3735F netbook
	SCRYPT_DEFAULT_N = 1 << 16
)

type scryptKdf struct {
	Salt   []byte
	N      int
	R      int
	P      int
	KeyLen int
}

func NewScryptKdf() scryptKdf {
	var s scryptKdf
	s.Salt = RandBytes(KEY_LEN)
	s.N = SCRYPT_DEFAULT_N
	s.R = 8 // Always 8
	s.P = 1 // Always 1
	s.KeyLen = KEY_LEN
	return s
}

func (s *scryptKdf) DeriveKey(pw string) []byte {
	k, err := scrypt.Key([]byte(pw), s.Salt, s.N, s.R, s.P, s.KeyLen)
	if err != nil {
		panic(fmt.Sprintf("DeriveKey failed: %s", err.Error()))
	}
	return k
}
