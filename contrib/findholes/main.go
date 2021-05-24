// Find and pretty-print holes & data sections of a file.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rfjakob/gocryptfs/contrib/findholes/holes"
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Printf("Usage: findholes FILE\n")
		os.Exit(1)
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		// os.Open() gives nicer error messages than syscall.Open()
		fmt.Println(err)
		os.Exit(1)
	}
	defer f.Close()

	segments, err := holes.Find(int(f.Fd()))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(holes.PrettyPrint(segments))
}
