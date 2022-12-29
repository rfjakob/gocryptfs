// Package ensurefds012 ensures that file descriptors 0,1,2 are open. It opens
// multiple copies of /dev/null as required.
// The Go stdlib as well as the gocryptfs code rely on the fact that
// fds 0,1,2 are always open.
//
// Use like this:
//
//	import _ "github.com/rfjakob/gocryptfs/v2/internal/ensurefds012"
//
// The import line MUST be in the alphabitcally first source code file of
// package main!
//
// You can test if it works as expected by inserting a long sleep into main,
// startings gocryptfs with all fds closed like this,
//
//	$ ./gocryptfs 0<&- 1>&- 2>&-
//
// and then checking the open fds. It should look like this:
//
//	$ ls -l /proc/$(pgrep gocryptfs)/fd
//	total 0
//	lrwx------. 1 jakob jakob 64 Jan  5 15:54 0 -> /dev/null
//	lrwx------. 1 jakob jakob 64 Jan  5 15:54 1 -> /dev/null
//	lrwx------. 1 jakob jakob 64 Jan  5 15:54 2 -> /dev/null
//	l-wx------. 1 jakob jakob 64 Jan  5 15:54 3 -> /dev/null
//	lrwx------. 1 jakob jakob 64 Jan  5 15:54 4 -> 'anon_inode:[eventpoll]'
//
// See https://github.com/rfjakob/gocryptfs/issues/320 for details.
package ensurefds012

import (
	"os"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

func init() {
	fd, err := syscall.Open("/dev/null", syscall.O_RDWR, 0)
	if err != nil {
		os.Exit(exitcodes.DevNull)
	}
	for fd <= 2 {
		fd, err = syscall.Dup(fd)
		if err != nil {
			os.Exit(exitcodes.DevNull)
		}
	}
	// Close excess fd (usually fd 3)
	syscall.Close(fd)
}
