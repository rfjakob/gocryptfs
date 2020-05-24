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
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

const (
	myName = "getdents"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s PATH\n", myName)
		fmt.Fprintf(os.Stderr, "Run getdents(2) on PATH\n")
		os.Exit(1)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}
	path := flag.Arg(0)

	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		log.Fatalf("unix.Open returned err=%v", err)
	}

	tmp := make([]byte, 10000)
	sum := 0
	for {
		n, err := unix.Getdents(fd, tmp)
		fmt.Printf("unix.Getdents fd%d: n=%d, err=%v\n", fd, n, err)
		if n <= 0 {
			fmt.Printf("total %d bytes\n", sum)
			break
		}
		sum += n
	}
}
