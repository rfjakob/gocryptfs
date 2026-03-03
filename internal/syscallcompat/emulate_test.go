package syscallcompat

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEmulateMknodat(t *testing.T) {
	err := emulateMknodat(tmpDirFd, "fifo1", unix.S_IFIFO, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/fifo1")
	if err != nil {
		t.Fatal(err)
	}
	// Test with absolute path
	err = emulateMknodat(-1, tmpDir+"/fifo2", unix.S_IFIFO, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(tmpDir + "/fifo2")
	if err != nil {
		t.Fatal(err)
	}
}
