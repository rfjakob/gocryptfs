package plaintextnames

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/rfjakob/gocryptfs/tests/test_helpers"

	"github.com/rfjakob/gocryptfs/contrib/findholes/holes"
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

// TestFileHoleCopy creates a sparse times, copies it a few times, and check if
// the copies are the same (including the location of holes and data sections).
//
// The test runs with -plaintextnames because that makes it easier to manipulate
// cipherdir directly.
func TestFileHoleCopy(t *testing.T) {
	n := "TestFileHoleCopy"
	pPath := []string{pDir + "/" + n}
	cPath := []string{cDir + "/" + n}

	f, err := os.Create(pPath[0])
	if err != nil {
		t.Fatal(err)
	}
	// | hole | x | hole | x | hole |
	buf := []byte("x")
	f.WriteAt(buf, 10000)
	f.WriteAt(buf, 30000)
	f.Truncate(50000)
	f.Sync()
	f.Close()

	// You have to update this value manually when you change the sequence
	// above
	md5 := test_helpers.Md5fn(pPath[0])
	if md5 != "4e8d0742bccfbcdbf1d71be688e4e81c" {
		t.Fatalf("wrong md5: %s", md5)
	}

	pSegments := []string{findHolesPretty(t, pPath[0])}
	cSegments := []string{findHolesPretty(t, cPath[0])}

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

	for i := range pSegments {
		t.Logf("pSegments[%d]: %s", i, pSegments[i])
		if i < len(pSegments)-1 {
			if pSegments[i+1] != pSegments[i] {
				t.Errorf("error: this is different than pSegments[%d]!", i+1)
			}
		}
	}
	t.Log("------------------------------------")
	for i := range cSegments {
		t.Logf("cSegments[%d]: %s", i, cSegments[i])
		if i < len(pSegments)-1 {
			if cSegments[i+1] != cSegments[i] {
				t.Errorf("error: this is different than cSegments[%d]!", i+1)
			}
		}
	}
}
