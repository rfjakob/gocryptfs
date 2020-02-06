package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	myName = "statvsfstat"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s PATH\n", myName)
		fmt.Fprintf(os.Stderr, "Dump the stat and fstat information for PATH to the console, JSON format.\n")
		os.Exit(1)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}
	path := flag.Arg(0)

	var st unix.Stat_t
	err := unix.Stat(path, &st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stat syscall returned error: %v\n", err)
		os.Exit(4)
	}

	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open syscall returned error: %v\n", err)
		os.Exit(3)
	}
	var fst unix.Stat_t
	err = unix.Fstat(fd, &fst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fstat syscall returned error: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("stat  result: %#v\n", st)
	fmt.Printf("fstat result: %#v\n", fst)
	if st == fst {
		fmt.Println("results are identical")
	} else {
		fmt.Println("results differ")
	}
}
