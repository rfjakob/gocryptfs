package contentenc

import (
	"fmt"
	"testing"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
)

// TestSizeToSize tests CipherSizeToPlainSize and PlainSizeToCipherSize
func TestSizeToSize(t *testing.T) {
	key := make([]byte, cryptocore.KeyLen)
	cc := cryptocore.New(key, cryptocore.BackendGoGCM, DefaultIVBits, true, false)
	ce := New(cc, DefaultBS, false)

	const rangeMax = 10000

	var c2p [rangeMax]uint64
	var p2c [rangeMax]uint64

	// Calculate values
	for i := range c2p {
		c2p[i] = ce.CipherSizeToPlainSize(uint64(i))
		p2c[i] = ce.PlainSizeToCipherSize(uint64(i))
	}

	// Print data table
	fmt.Print("x\tToPlainSize\tToCipherSize\n")
	for i := range c2p {
		if i > 1 && i < rangeMax-1 {
			// If the point before has value-1 and the point after has value+1,
			// it is not interesting. Don't print it out.
			if c2p[i] == c2p[i-1]+1 && p2c[i] == p2c[i-1]+1 && c2p[i+1] == c2p[i]+1 && p2c[i+1] == p2c[i]+1 {
				continue
			}
		}
		fmt.Printf("%d\t%d\t%d\n", i, c2p[i], p2c[i])
	}

	// Monotonicity check
	for i := range c2p {
		if i < 1 {
			continue
		}
		if c2p[i-1] > c2p[i] {
			t.Errorf("error: c2p is non-monotonic: c2p[%d]=%d c2p[%d]=%d ", i-1, c2p[i-1], i, c2p[i])
		}
		if p2c[i-1] > p2c[i] {
			t.Errorf("error: p2c is non-monotonic: p2c[%d]=%d p2c[%d]=%d ", i-1, p2c[i-1], i, p2c[i])
		}
	}
}
