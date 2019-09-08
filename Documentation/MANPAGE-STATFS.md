% STATFS(1)
% github.com/rfjakob
% Sep 2019

NAME
====

statfs - dump the statfs(2) information for PATH to console in JSON format.

SYNOPSIS
========

statfs PATH

DESCRIPTION
===========

The statfs(2) system call returns information about a mounted filesystem
in a `statfs_t` structure. This tool dumps this information in JSON format.
It is developed as part of gocryptfs and written in Go.

The `statfs_t` structure is architecture-dependent. On amd64 it looks like this:

```
type Statfs_t struct {
	Type   int64
	Bsize  int64
	Blocks uint64
	Bfree  uint64
	Bavail uint64
	Files  uint64
	Ffree  uint64
	Fsid   struct {
		Val [2]int32
	}
	Namelen int64
	Frsize  int64
	Flags   int64
	Spare   [4]int64
}
```

See the statfs(2) man page for the meaning of these fields, and note
that the field names here are acc. to the Go `golang.org/x/sys/unix`
naming convention, and slightly different than in C.

EXAMPLES
========

Get the statfs(2) information for /tmp:

```
$ statfs /tmp
{
	"Type": 16914836,
	"Bsize": 4096,
	"Blocks": 3067428,
	"Bfree": 3067411,
	"Bavail": 3067411,
	"Files": 3067428,
	"Ffree": 3067381,
	"Fsid": {
		"Val": [
			0,
			0
		]
	},
	"Namelen": 255,
	"Frsize": 4096,
	"Flags": 38,
	"Spare": [
		0,
		0,
		0,
		0
	]
}
```

SEE ALSO
========
statfs(2) gocryptfs(1)
