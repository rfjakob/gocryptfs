package syscallcompat

import (
	"fmt"
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// asUser runs `f()` under the effective uid, gid, groups specified
// in `context`.
//
// If `context` is nil, `f()` is executed directly without switching user id.
func asUser(f func() (int, error), context *fuse.Context) (int, error) {
	if context == nil {
		return f()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Since go1.16beta1 (commit d1b1145cace8b968307f9311ff611e4bb810710c ,
	// https://go-review.googlesource.com/c/go/+/210639 )
	// syscall.{Setgroups,Setregid,Setreuid} affects all threads, which
	// is exactly what we not want.
	//
	// We now use unix.{Setgroups,Setregid,Setreuid} instead.

	err := unix.Setgroups(getSupplementaryGroups(context.Pid))
	if err != nil {
		return -1, err
	}
	defer unix.Setgroups(nil)

	err = unix.Setregid(-1, int(context.Owner.Gid))
	if err != nil {
		return -1, err
	}
	defer unix.Setregid(-1, 0)

	err = unix.Setreuid(-1, int(context.Owner.Uid))
	if err != nil {
		return -1, err
	}
	defer unix.Setreuid(-1, 0)

	return f()
}

func getSupplementaryGroups(pid uint32) (gids []int) {
	procPath := fmt.Sprintf("/proc/%d/task/%d/status", pid, pid)
	blob, err := ioutil.ReadFile(procPath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(blob), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Groups:") {
			f := strings.Fields(line[7:])
			gids = make([]int, len(f))
			for i := range gids {
				val, err := strconv.ParseInt(f[i], 10, 32)
				if err != nil {
					return nil
				}
				gids[i] = int(val)
			}
			return gids
		}
	}

	return nil
}
