package syscallcompat

import (
	"github.com/hanwen/go-fuse/v2/fuse"
)

// asUser runs `f()` under the effective uid, gid, groups specified
// in `context`.
//
// If `context` is nil, `f()` is executed directly without switching user id.
//
// WARNING this function is not complete, and always runs f() as if context is nil.
// FreeBSD does not support changing uid/gid per thread.
func asUser(f func() (int, error), context *fuse.Context) (int, error) {
	return f()
}
