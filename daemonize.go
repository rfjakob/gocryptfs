package main

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/rfjakob/gocryptfs/cryptfs"
)

// The child sends us USR1 if the mount was successful
func exitOnUsr1() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	<-c
	os.Exit(0)
}

// forkChild - execute ourselves once again, this time with the "-f" flag, and
// wait for SIGUSR1 or child exit.
// This is a workaround for the missing true fork function in Go.
func forkChild() {
	go exitOnUsr1()
	name := os.Args[0]
	newArgs := []string{"-f", fmt.Sprintf("-notifypid=%d", os.Getpid())}
	newArgs = append(newArgs, os.Args[1:]...)
	c := exec.Command(name, newArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	err := c.Start()
	if err != nil {
		fmt.Printf("forkChild: starting %s failed: %v\n", name, err)
		os.Exit(1)
	}
	err = c.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if waitstat, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				os.Exit(waitstat.ExitStatus())
			}
		}
		fmt.Printf("forkChild: wait returned an unknown error: %v\n", err)
		os.Exit(1)
	}
	// The child exited with 0 - let's do the same.
	os.Exit(0)
}

// Switch one Logger to syslog
func switchToSyslog(l *log.Logger, p syslog.Priority) {
	w, err := syslog.New(p, PROGRAM_NAME)
	if err != nil {
		cryptfs.Warn.Printf("Cannot switch 0x%02x to syslog: %v", p, err)
	} else {
		l.SetOutput(w)
	}
}
