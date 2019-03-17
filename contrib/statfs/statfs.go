package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"syscall"
)

const (
	myName = "statfs"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s PATH\n", myName)
		fmt.Fprintf(os.Stderr, "Dump the statfs information for PATH to the console, JSON format.\n")
		os.Exit(1)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
	}
	path := flag.Arg(0)
	var st syscall.Statfs_t
	err := syscall.Statfs(path, &st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "statfs syscall returned error: %v\n", err)
		os.Exit(2)
	}
	jsn, _ := json.MarshalIndent(st, "", "\t")
	fmt.Println(string(jsn))
}
