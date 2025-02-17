//go:build linux

// golang.org/x/sys/unix commit
// https://github.com/golang/sys/commit/d0df966e6959f00dc1c74363e537872647352d51
// changed unix.Setreuid/unix.Setregid functions to affect the whole thread, which is
// what gocryptfs does NOT want (https://github.com/rfjakob/gocryptfs/issues/893).
// The functions Setreuid/Setegid are copy-pasted from one commit before
// (9e1f76180b77a12eb07c82eb8e1ea8a7f8d202e7).
//
// Looking at the diff at https://github.com/golang/sys/commit/d0df966e6959f00dc1c74363e537872647352d51
// we see that only two architectures, 386 and arm, use SYS_SETREUID32/SYS_SETREGID32
// (see "man 2 setreuid" for why).
// All the others architectures use SYS_SETREUID/SYS_SETREGID.
//
// As of golang.org/x/sys/unix v0.30.0, Setgroups/setgroups is still per-thread, but
// it is likely that this will change, too. Setgroups/setgroups are copy-pasted from
// v0.30.0. The SYS_SETGROUPS32/SYS_SETGROUPS split is the same as for Setreuid.
//
// Note: _Gid_t is always uint32 on linux, so we can directly use uint32 for setgroups.
package syscallcompat

import (
	"log"
)

func Setgroups(gids []int) (err error) {
	if len(gids) == 0 {
		return setgroups(0, nil)
	}

	a := make([]uint32, len(gids))
	for i, v := range gids {
		a[i] = uint32(v)
	}
	return setgroups(len(a), &a[0])
}

// SetgroupsPanic calls Setgroups and panics on error
func SetgroupsPanic(gids []int) {
	err := Setgroups(gids)
	if err != nil {
		log.Panic(err)
	}
}

// SetregidPanic calls Setregid and panics on error
func SetregidPanic(rgid int, egid int) {
	err := Setregid(rgid, egid)
	if err != nil {
		log.Panic(err)
	}
}

// SetreuidPanic calls Setreuid and panics on error
func SetreuidPanic(ruid int, euid int) {
	err := Setreuid(ruid, euid)
	if err != nil {
		log.Panic(err)
	}
}
