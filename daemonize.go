package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// The child sends us USR1 if the mount was successful
func waitForUsr1() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	<-c
	os.Exit(0)
}

// daemonize - execute ourselves once again, this time with the "-f" flag, and
// wait for SIGUSR1.
func daemonize() {
	go waitForUsr1()
	name := os.Args[0]
	notifyArg := fmt.Sprintf("-notifypid=%d", os.Getpid())
	newArgs := []string{"-f", notifyArg}
	newArgs = append(newArgs, os.Args[1:]...)
	c := exec.Command(name, newArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	err := c.Start()
	if err != nil {
		fmt.Printf("daemonize: starting %s failed: %v\n", name, err)
		os.Exit(1)
	}
	err = c.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if waitstat, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				os.Exit(waitstat.ExitStatus())
			}
		}
		fmt.Printf("daemonize: wait returned an unknown error: %v\n", err)
		os.Exit(1)
	}
	// The child exited with 0 - let's do the same.
	os.Exit(0)
}
