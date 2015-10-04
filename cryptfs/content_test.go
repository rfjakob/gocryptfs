package cryptfs

import (
	"testing"
	"fmt"
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
		testRange{6654, 8945})

	key := make([]byte, 16)
	f := NewCryptFS(key, true)

	for _, r := range(ranges) {
		parts := f.SplitRange(r.offset, r.length)
		for _, p := range(parts) {
			if p.Length > DEFAULT_PLAINBS || p.Offset >= DEFAULT_PLAINBS {
				fmt.Printf("Test fail: n=%d, length=%d, offset=%d\n", p.BlockNo, p.Length, p.Offset)
				t.Fail()
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

	key := make([]byte, 16)
	f := NewCryptFS(key, true)

	for _, r := range(ranges) {
		alignedOffset, alignedLength, skipBytes := f.CiphertextRange(r.offset, r.length)
		if alignedLength < r.length {
			t.Fail()
		}
		if alignedOffset % f.cipherBS != 0 {
			t.Fail()
		}
		if r.offset % f.plainBS != 0 && skipBytes == 0 {
			t.Fail()
		}
	}
}

func TestBlockNo(t *testing.T) {
	key := make([]byte, 16)
	f := NewCryptFS(key, true)

	b := f.BlockNoCipherOff(788)
	if b != 0 {
		t.Errorf("actual: %d", b)
	}
	b = f.BlockNoCipherOff(f.CipherBS())
	if b != 1 {
		t.Errorf("actual: %d", b)
	}
	b = f.BlockNoPlainOff(788)
	if b != 0 {
		t.Errorf("actual: %d", b)
	}
	b = f.BlockNoPlainOff(f.PlainBS())
	if b != 1 {
		t.Errorf("actual: %d", b)
	}
}
