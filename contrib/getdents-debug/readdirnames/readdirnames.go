/*
Small tool to try to debug unix.Getdents problems on CIFS mounts
( https://github.com/rfjakob/gocryptfs/issues/483 )

Example output:

$ while sleep 1 ; do ./readdirnames /mnt/synology/public/tmp/g1 ; done
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
Readdirnames: len=868, err=readdirent: no such file or directory
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
2020/05/24 23:50:39 os.Open returned err=open /mnt/synology/public/tmp/g1: interrupted system call
Readdirnames: len=1001, err=<nil>
Readdirnames: len=1001, err=<nil>
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

const (
	myName = "readdirnames"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s PATH\n", myName)
		fmt.Fprintf(os.Stderr, "Run os.File.Readdirnames on PATH\n")
		os.Exit(1)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}
	path := flag.Arg(0)

	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("os.Open returned err=%v", err)
	}

	names, err := f.Readdirnames(0)
	fmt.Printf("Readdirnames: len=%d, err=%v\n", len(names), err)
}
