package syscallcompat

import (
	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// asUser runs `f()` under the effective uid, gid, groups specified
// in `context`.
//
// If `context` is nil, `f()` is executed directly without switching user id.
//
// FreeBSD does not support changing uid/gid per thread. If context is not nil,
// an error is returned.
func asUser(f func() (int, error), context *fuse.Context) (int, error) {
	if context == nil {
		return f()
	}
	tlog.Warn.Printf("asUser: error, only nil context is supported\n")
	return 0, unix.EOPNOTSUPP
}
