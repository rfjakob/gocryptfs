package plaintextnames

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"

	"github.com/rfjakob/gocryptfs/v2/contrib/findholes/holes"
)

func findHolesPretty(t *testing.T, path string) string {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	segments, err := holes.Find(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}

	return holes.PrettyPrint(segments)
}

func doTestFileHoleCopy(t *testing.T, name string, writeOffsets []int64) {
	n := "TestFileHoleCopy." + name
	pPath := []string{pDir + "/" + n}
	cPath := []string{cDir + "/" + n}

	os.Remove(pPath[0])
	holes.Create(pPath[0])

	// expected md6
	md5 := test_helpers.Md5fn(pPath[0])

	pSegments := []string{findHolesPretty(t, pPath[0])}
	cSegments := []string{findHolesPretty(t, cPath[0])}

	// create 5 more copies
	for i := 1; i < 5; i++ {
		pPath = append(pPath, fmt.Sprintf("%s.%d", pPath[0], i))
		cPath = append(cPath, fmt.Sprintf("%s.%d", cPath[0], i))

		out, err := exec.Command("cp", "--sparse=auto", pPath[i-1], pPath[i]).CombinedOutput()
		if err != nil {
			t.Fatal(string(out))
		}

		tmp := test_helpers.Md5fn(pPath[0])
		if tmp != md5 {
			t.Errorf("pPath[%d]: wrong md5, have %s, want %s", i, tmp, md5)
		}

		pSegments = append(pSegments, findHolesPretty(t, pPath[i]))
		cSegments = append(cSegments, findHolesPretty(t, cPath[i]))
	}

	// "cp --sparse=auto" checks of the file has fewer blocks on disk than it
	// should have for its size. Only then it will try to create a sparse copy.
	var st syscall.Stat_t
	err := syscall.Stat(pPath[0], &st)
	if err != nil {
		t.Fatal(err)
	}
	// convert 512 byte blocks to 4k blocks
	blocks4k := st.Blocks / 8
	// For more than a few fragments, ext4 allocates one extra block
	blocks4k++
	if blocks4k >= (st.Size+4095)/4096 {
		t.Logf("file will look non-sparse to cp, skipping segment check")
		return
	}

	// Check that size on disk stays the same across copies
	var st0 syscall.Stat_t
	if err := syscall.Stat(pPath[0], &st0); err != nil {
		t.Fatal(err)
	}
	for i := range pSegments {
		var st syscall.Stat_t
		if err := syscall.Stat(pPath[i], &st); err != nil {
			t.Fatal(err)
		}
		// Size on disk fluctuates by +-4kB due to different number of extents
		// (looking at "filefrag -v", it seems like ext4 needs 4kB extra once
		//  you have >=4 extents)
		if st.Blocks != st0.Blocks && st.Blocks != st0.Blocks-8 && st.Blocks != st0.Blocks+8 {
			t.Errorf("size changed: st0.Blocks=%d st%d.Blocks=%d", st0.Blocks, i, st.Blocks)
		}
	}

	// Check that hole/data segments stays the same across copies
	out := ""
	same := true
	for i := range pSegments {
		out += fmt.Sprintf("pSegments[%d]:\n%s\n", i, pSegments[i])
		if i < len(pSegments)-1 {
			if pSegments[i+1] != pSegments[i] {
				same = false
				t.Errorf("error: pSegments[%d] is different than pSegments[%d]!", i, i+1)
			}
		}
	}
	out += "------------------------------------\n"
	for i := range cSegments {
		out += fmt.Sprintf("cSegments[%d]:\n%s\n", i, cSegments[i])
		if i < len(pSegments)-1 {
			if cSegments[i+1] != cSegments[i] {
				same = false
				t.Errorf("error: cSegments[%d] is different than cSegments[%d]!", i, i+1)
			}
		}
	}
	if !same {
		t.Log(out)
	}
}

// TestFileHoleCopy creates a sparse times, copies it a few times, and check if
// the copies are the same (including the location of holes and data sections).
//
// The test runs with -plaintextnames because that makes it easier to manipulate
// cipherdir directly.
func TestFileHoleCopy(t *testing.T) {
	// | hole | x | hole | x | hole |
	// truncate -s 50000 foo && dd if=/dev/zero of=foo bs=1 seek=10000 count=1 conv=notrunc && dd if=/dev/zero of=foo bs=1 seek=30000 count=1 conv=notrunc
	name := "c0"
	c0 := []int64{10000, 30000}
	if !t.Run("c0", func(t *testing.T) { doTestFileHoleCopy(t, name, c0) }) {
		t.Log("aborting further subtests")
		return
	}

	rand.Seed(time.Now().UnixNano())
	for k := 0; k < 100; k++ {
		c1 := make([]int64, 10)
		for i := range c1 {
			c1[i] = int64(rand.Int31n(60000))
		}
		name := fmt.Sprintf("k%d", k)
		if !t.Run(name, func(t *testing.T) { doTestFileHoleCopy(t, name, c1) }) {
			t.Log("aborting further subtests")
			return
		}
	}
}
