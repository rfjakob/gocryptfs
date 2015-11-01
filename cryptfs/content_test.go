package cryptfs

import (
	"testing"
)

type testRange struct {
	offset uint64
	length uint64
}

func TestSplitRange(t *testing.T) {
	var ranges []testRange

	ranges = append(ranges, testRange{0, 70000},
		testRange{0, 10},
		testRange{234, 6511},
		testRange{65444, 54},
		testRange{0, 1024 * 1024},
		testRange{0, 65536},
		testRange{6654, 8945})

	key := make([]byte, KEY_LEN)
	f := NewCryptFS(key, true)

	for _, r := range ranges {
		parts := f.ExplodePlainRange(r.offset, r.length)
		var lastBlockNo uint64 = 1 << 63
		for _, p := range parts {
			if p.BlockNo == lastBlockNo {
				t.Errorf("Duplicate block number %d", p.BlockNo)
			}
			lastBlockNo = p.BlockNo
			if p.Length > DEFAULT_PLAINBS || p.Skip >= DEFAULT_PLAINBS {
				t.Errorf("Test fail: n=%d, length=%d, offset=%d\n", p.BlockNo, p.Length, p.Skip)
			}
		}
	}
}

func TestCiphertextRange(t *testing.T) {
	var ranges []testRange

	ranges = append(ranges, testRange{0, 70000},
		testRange{0, 10},
		testRange{234, 6511},
		testRange{65444, 54},
		testRange{6654, 8945})

	key := make([]byte, KEY_LEN)
	f := NewCryptFS(key, true)

	for _, r := range ranges {

		blocks := f.ExplodePlainRange(r.offset, r.length)
		alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
		skipBytes := blocks[0].Skip

		if alignedLength < r.length {
			t.Errorf("alignedLength=%s is smaller than length=%d", alignedLength, r.length)
		}
		if (alignedOffset-HEADER_LEN)%f.cipherBS != 0 {
			t.Errorf("alignedOffset=%d is not aligned", alignedOffset)
		}
		if r.offset%f.plainBS != 0 && skipBytes == 0 {
			t.Errorf("skipBytes=0")
		}
	}
}

func TestBlockNo(t *testing.T) {
	key := make([]byte, KEY_LEN)
	f := NewCryptFS(key, true)

	b := f.CipherOffToBlockNo(788)
	if b != 0 {
		t.Errorf("actual: %d", b)
	}
	b = f.CipherOffToBlockNo(HEADER_LEN + f.cipherBS)
	if b != 1 {
		t.Errorf("actual: %d", b)
	}
	b = f.PlainOffToBlockNo(788)
	if b != 0 {
		t.Errorf("actual: %d", b)
	}
	b = f.PlainOffToBlockNo(f.plainBS)
	if b != 1 {
		t.Errorf("actual: %d", b)
	}
}
