package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
)

const fileCount = 100

type stats struct {
	renameOk            int
	renameError         int
	readOk              int
	readError           int
	readContentMismatch int
}

func usage() {
	fmt.Printf(`atomicrename creates %d "src" files in the current directory, renames
them in random order over a single "dst" file while reading the "dst"
file concurrently in a loop.

Progress and errors are reported as they occur in addition to a summary
printed at the end. cifs and fuse filesystems are known to fail, local
filesystems and nfs seem ok.

See https://github.com/hanwen/go-fuse/issues/398 for background info.
`, fileCount)
	os.Exit(1)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	hello := []byte("hello world")
	srcFiles := make(map[string]struct{})

	// prepare source files
	fmt.Print("creating files")
	for i := 0; i < fileCount; i++ {
		srcName := fmt.Sprintf("src.atomicrename.%d", i)
		srcFiles[srcName] = struct{}{}
		buf := bytes.Repeat([]byte("_"), i)
		buf = append(buf, hello...)
		if err := ioutil.WriteFile(srcName, buf, 0600); err != nil {
			panic(err)
		}
		fmt.Print(".")
	}
	fmt.Print("\n")

	// prepare destination file
	const dstName = "dst.atomicrename"
	if err := ioutil.WriteFile(dstName, hello, 0600); err != nil {
		panic(err)
	}

	var running int32 = 1

	stats := stats{}

	// read thread
	go func() {
		for atomic.LoadInt32(&running) == 1 {
			have, err := ioutil.ReadFile(dstName)
			if err != nil {
				fmt.Println(err)
				stats.readError++
				continue
			}
			if !strings.HasSuffix(string(have), string(hello)) {
				fmt.Printf("content mismatch: have %q\n", have)
				stats.readContentMismatch++
				continue
			}
			fmt.Printf("content ok len=%d\n", len(have))
			stats.readOk++
		}
	}()

	// rename thread = main thread
	for srcName := range srcFiles {
		if err := os.Rename(srcName, dstName); err != nil {
			fmt.Println(err)
			stats.renameError++
		}
		stats.renameOk++
	}
	// Signal the Read goroutine to stop when loop is done
	atomic.StoreInt32(&running, 0)

	syscall.Unlink(dstName)
	fmt.Printf("stats: %#v\n", stats)
}
