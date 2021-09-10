package contentenc

import (
	"fmt"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
)

// TestSizeToSize tests CipherSizeToPlainSize and PlainSizeToCipherSize
func TestSizeToSize(t *testing.T) {
	key := make([]byte, cryptocore.KeyLen)
	cc := cryptocore.New(key, cryptocore.BackendGoGCM, DefaultIVBits, true)
	ce := New(cc, DefaultBS)

	const rangeMax = 10000

	// y values in this order:
	// 0 ... CipherSizeToPlainSize
	// 1 ... PlainSizeToCipherSize
	// 2 ... PlainOffToCipherOff
	var yTable [rangeMax][3]uint64

	// Calculate values
	for x := range yTable {
		yTable[x][0] = ce.CipherSizeToPlainSize(uint64(x))
		yTable[x][1] = ce.PlainSizeToCipherSize(uint64(x))
		yTable[x][2] = ce.PlainOffToCipherOff(uint64(x))
	}

	// Print data table
	fmt.Print("x\tCipherSizeToPlainSize\tPlainSizeToCipherSize\tPlainOffToCipherOff\n")
	for x := range yTable {
		if x > 1 && x < rangeMax-1 {
			// If the point before has value-1 and the point after has value+1,
			// it is not interesting. Don't print it out.
			interesting := false
			for i := 0; i <= 2; i++ {
				if yTable[x-1][i]+1 != yTable[x][i] && yTable[x][i]+1 != yTable[x+1][i]+1 {
					interesting = true
				}
				// Monotonicity check
				if yTable[x][i] < yTable[x-1][i] {
					t.Errorf("column %d is non-monotonic!", i)
				}
			}
			if !interesting {
				continue
			}
		}
		fmt.Printf("%d\t%d\t%d\t%d\n", x, yTable[x][0], yTable[x][1], yTable[x][2])
	}
}
