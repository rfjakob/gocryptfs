package syscallcompat

import (
	"bytes"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestReadlinkat(t *testing.T) {
	for _, targetLen := range []int{100, 500, 4000} {
		target := string(bytes.Repeat([]byte("x"), targetLen))
		err := os.Symlink(target, tmpDir+"/readlinkat")
		if err != nil {
			if targetLen > 1000 && runtime.GOOS == "darwin" {
				// Symlinks longer than 1024 (?) bytes are not supported on
				// MacOS
				continue
			}
			t.Fatal(err)
		}
		target2, err := Readlinkat(tmpDirFd, "readlinkat")
		if err != nil {
			t.Fatal(err)
		}
		if target != target2 {
			t.Errorf("target=%q != target2=%q", target, target2)
		}
		err = syscall.Unlink(tmpDir + "/readlinkat")
		if err != nil {
			t.Fatal(err)
		}
	}
}
