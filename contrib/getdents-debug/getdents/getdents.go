/*
Small tool to try to debug unix.Getdents problems on CIFS mounts
( https://github.com/rfjakob/gocryptfs/issues/483 )

Example output:

$ while sleep 1 ; do ./getdents /mnt/synology/public/tmp/g1 ; done
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=3192, err=<nil>
unix.Getdents fd3: n=0, err=<nil>
total 24072 bytes
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=-1, err=no such file or directory
total 16704 bytes
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=4176, err=<nil>
unix.Getdents fd3: n=3192, err=<nil>
unix.Getdents fd3: n=0, err=<nil>
total 24072 bytes


Failure looks like this in strace:

[pid 189974] getdents64(6, 0xc000105808, 10000) = -1 ENOENT (No such file or directory)
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	myName = "getdents"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s PATH\n", myName)
		fmt.Fprintf(os.Stderr, "Run getdents(2) on PATH in a 100ms loop until we hit an error\n")
		os.Exit(1)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}
	path := flag.Arg(0)

	tmp := make([]byte, 10000)
	for i := 1; ; i++ {
		sum := 0
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err != nil {
			fmt.Printf("%3d: unix.Open returned err=%v\n", i, err)
			os.Exit(1)
		}
		fmt.Printf("%3d: unix.Getdents: ", i)
		for {
			n, err := unix.Getdents(fd, tmp)
			fmt.Printf("n=%d; ", n)
			if n <= 0 {
				fmt.Printf("err=%v; total %d bytes\n", err, sum)
				if err != nil {
					os.Exit(1)
				}
				break
			}
			sum += n
		}
		unix.Close(fd)
		time.Sleep(100 * time.Millisecond)
	}
}
