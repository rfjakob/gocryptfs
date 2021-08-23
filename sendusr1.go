package main

import (
	"os"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// Send signal USR1 to "pid" (usually our parent process). This notifies it
// that the mounting has completed successfully.
func sendUsr1(pid int) {
	p, err := os.FindProcess(pid)
	if err != nil {
		tlog.Warn.Printf("sendUsr1: FindProcess: %v\n", err)
		return
	}
	err = p.Signal(syscall.SIGUSR1)
	if err != nil {
		tlog.Warn.Printf("sendUsr1: Signal: %v\n", err)
	}
}
