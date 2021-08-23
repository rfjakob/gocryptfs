package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// The child sends us USR1 if the mount was successful. Exit with error code
// 0 if we get it.
func exitOnUsr1() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	go func() {
		<-c
		os.Exit(0)
	}()
}

// forkChild - execute ourselves once again, this time with the "-fg" flag, and
// wait for SIGUSR1 or child exit.
// This is a workaround for the missing true fork function in Go.
func forkChild() int {
	name := os.Args[0]
	// Use the full path to our executable if we can get if from /proc.
	buf := make([]byte, syscallcompat.PATH_MAX)
	n, err := syscall.Readlink("/proc/self/exe", buf)
	if err == nil {
		name = string(buf[:n])
		tlog.Debug.Printf("forkChild: readlink worked: %q", name)
	}
	newArgs := []string{"-fg", fmt.Sprintf("-notifypid=%d", os.Getpid())}
	newArgs = append(newArgs, os.Args[1:]...)
	c := exec.Command(name, newArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	exitOnUsr1()
	err = c.Start()
	if err != nil {
		tlog.Fatal.Printf("forkChild: starting %s failed: %v", name, err)
		return exitcodes.ForkChild
	}
	err = c.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if waitstat, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				os.Exit(waitstat.ExitStatus())
			}
		}
		tlog.Fatal.Printf("forkChild: wait returned an unknown error: %v", err)
		return exitcodes.ForkChild
	}
	// The child exited with 0 - let's do the same.
	return 0
}

// redirectStdFds redirects stderr and stdout to syslog; stdin to /dev/null
func redirectStdFds() {
	// Create a pipe pair "pw" -> "pr" and start logger reading from "pr".
	// We do it ourselves instead of using StdinPipe() because we need access
	// to the fd numbers.
	pr, pw, err := os.Pipe()
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: could not create pipe: %v\n", err)
		return
	}
	tag := fmt.Sprintf("gocryptfs-%d-logger", os.Getpid())
	cmd := exec.Command("logger", "-t", tag)
	cmd.Stdin = pr
	err = cmd.Start()
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: could not start logger: %v\n", err)
		return
	}
	// The logger now reads on "pr". We can close it.
	pr.Close()
	// Redirect stout and stderr to "pw".
	err = syscallcompat.Dup3(int(pw.Fd()), 1, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stdout dup error: %v\n", err)
	}
	syscallcompat.Dup3(int(pw.Fd()), 2, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stderr dup error: %v\n", err)
	}
	// Our stout and stderr point to "pw". We can close the extra copy.
	pw.Close()
	// Redirect stdin to /dev/null
	nullFd, err := os.Open("/dev/null")
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: could not open /dev/null: %v\n", err)
		return
	}
	err = syscallcompat.Dup3(int(nullFd.Fd()), 0, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stdin dup error: %v\n", err)
	}
	nullFd.Close()
}
