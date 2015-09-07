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

	var key [16]byte
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
