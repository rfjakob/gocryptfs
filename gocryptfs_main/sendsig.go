package main

import (
	"syscall"
	"bytes"
	"fmt"
	"os"
	"io/ioutil"
)

// cmdline looks like this: /bin/bash \0 /path/to/gocryptfs \0 --zerokey \0 ...
const (
	WRAPPER_PREFIX =  "/bin/bash\000"
	WRAPPER_CONTAINS = "gocryptfs\000"
)

// Send USR1 to the "gocryptfs" wrapper shell script. This notifies it that the
// mounting has completed sucessfully.
//
// Checks /proc/$PPID/cmdline to make sure we do not kill an unrelated process.
func sendSig() {
	ppid := os.Getppid()
	fn := fmt.Sprintf("/proc/%d/cmdline", ppid)
	cmdline, err := ioutil.ReadFile(fn)
	if err != nil {
		fmt.Printf("sendSig: ReadFile: %v\n", err)
		return
	}
	if bytes.HasPrefix(cmdline, []byte(WRAPPER_PREFIX)) && bytes.Contains(cmdline, []byte(WRAPPER_CONTAINS)) {
		p, err := os.FindProcess(ppid)
		if err != nil {
			fmt.Printf("sendSig: FindProcess: %v\n", err)
			return
		}
		err = p.Signal(syscall.SIGUSR1)
		if err != nil {
			fmt.Printf("sendSig: Signal: %v\n", err)
		}
	} else {
		fmt.Printf("Not running under the gocryptfs wrapper - will not daemonize\n")
	}
}
