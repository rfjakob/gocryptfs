package syscallcompat

import (
	"fmt"
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"

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
	// And unix.{Setgroups,Setregid,Setreuid} also changed to this behavoir in
	// v0.1.0 (commit d0df966e6959f00dc1c74363e537872647352d51 ,
	// https://go-review.googlesource.com/c/sys/+/428174 ), so we use
	// our own syscall wrappers.

	err := Setgroups(getSupplementaryGroups(context.Pid))
	if err != nil {
		return -1, err
	}
	defer SetgroupsPanic(nil)

	err = Setregid(-1, int(context.Owner.Gid))
	if err != nil {
		return -1, err
	}
	defer SetregidPanic(-1, 0)

	err = Setreuid(-1, int(context.Owner.Uid))
	if err != nil {
		return -1, err
	}
	defer SetreuidPanic(-1, 0)

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
