package nametransform

import (
	"strings"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
)

func TestIsLongName(t *testing.T) {
	n := "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU=.name"
	if NameType(n) != LongNameFilename {
		t.Errorf("False negative")
	}

	n = "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if NameType(n) != LongNameContent {
		t.Errorf("False negative")
	}

	n = "LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if NameType(n) != LongNameNone {
		t.Errorf("False positive")
	}
}

func TestRemoveLongNameSuffix(t *testing.T) {
	filename := "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU=.name"
	content := "gocryptfs.longname.LkwUdALvV_ANnzQN6ZZMYnxxfARD3IeZWCKnxGJjYmU="
	if RemoveLongNameSuffix(filename) != content {
		t.Error(".name suffix not removed")
	}
}

func newLognamesTestInstance(longNameMax uint8) *NameTransform {
	key := make([]byte, cryptocore.KeyLen)
	cCore := cryptocore.New(key, cryptocore.BackendGoGCM, contentenc.DefaultIVBits, true)
	return New(cCore.EMECipher, true, longNameMax, true, nil, false)
}

func TestLongNameMax(t *testing.T) {
	iv := make([]byte, 16)
	for max := 0; max <= NameMax; max++ {
		n := newLognamesTestInstance(uint8(max))
		if max == 0 {
			// effective value is 255
			max = NameMax
		}
		for l := 0; l <= NameMax+10; l++ {
			name := strings.Repeat("x", l)
			out, err := n.EncryptAndHashName(name, iv)
			if l == 0 || l > NameMax {
				if err == nil {
					t.Errorf("should have rejected a name of length %d, but did not", l)
				}
				continue
			}
			cName, _ := n.EncryptName(name, iv)
			rawLen := len(cName)
			want := LongNameNone
			if rawLen > max {
				want = LongNameContent
			}
			have := NameType(out)
			if have != want {
				t.Errorf("l=%d max=%d: wanted %v, got %v\nname=%q\nout=%q", l, max, want, have, name, out)
			}
		}
	}
}
