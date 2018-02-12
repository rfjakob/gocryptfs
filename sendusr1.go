package main

import (
	"os"
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Send signal USR1 to "pid" (usually our parent process). This notifies it
// that the mounting has completed successfully.
func sendUsr1(pid int) {
	p, err := os.FindProcess(pid)
	if err != nil {
		tlog.Warn.Printf("sendUsr1: FindProcess: %v\n", err)
		return
	}
	err = p.Signal(unix.SIGUSR1)
	if err != nil {
		tlog.Warn.Printf("sendUsr1: Signal: %v\n", err)
	}
}
