// Find and pretty-print holes & data sections of a file.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rfjakob/gocryptfs/v2/contrib/findholes/holes"
)

func main() {
	flags := struct {
		verify *bool
		create *bool
	}{}
	flags.verify = flag.Bool("verify", false, "Verify results using full file scan")
	flags.create = flag.Bool("create", false, "Create test file with random holes")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Printf("Usage: findholes FILE\n")
		os.Exit(1)
	}

	path := flag.Arg(0)

	if *flags.create {
		holes.Create(path)
	}

	f, err := os.Open(path)
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

	if *flags.verify {
		err = holes.Verify(int(f.Fd()), segments)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			fmt.Println("verify ok")
		}
	}

}
