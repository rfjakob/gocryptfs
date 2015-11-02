package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
)

const (
	wrapperContains = "gocryptfs\000"
)

// Send USR1 to the parent process. This notifies it that the
// mounting has completed sucessfully.
//
// Checks /proc/$PPID/cmdline to make sure we do not kill an unrelated process.
func sendUsr1() {
	ppid := os.Getppid()
	fn := fmt.Sprintf("/proc/%d/cmdline", ppid)
	cmdline, err := ioutil.ReadFile(fn)
	if err != nil {
		fmt.Printf("sendUsr1: ReadFile: %v\n", err)
		return
	}
	if bytes.Contains(cmdline, []byte(wrapperContains)) {
		p, err := os.FindProcess(ppid)
		if err != nil {
			fmt.Printf("sendUsr1: FindProcess: %v\n", err)
			return
		}
		err = p.Signal(syscall.SIGUSR1)
		if err != nil {
			fmt.Printf("sendUsr1: Signal: %v\n", err)
		}
	}
}
