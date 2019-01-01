package test_helpers

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Indexed by mountpoint. Initialized in doInit().
var MountInfo map[string]mountInfo

type mountInfo struct {
	// PID of the running gocryptfs process. Set by Mount().
	pid int
	// List of open FDs of the running gocrypts process. Set by Mount().
	fds []string
}

// Mount CIPHERDIR "c" on PLAINDIR "p"
// Creates "p" if it does not exist.
func Mount(c string, p string, showOutput bool, extraArgs ...string) error {
	args := []string{"-q", "-wpanic", "-nosyslog", "-fg", fmt.Sprintf("-notifypid=%d", os.Getpid())}
	args = append(args, extraArgs...)
	//args = append(args, "-fusedebug")
	//args = append(args, "-d")
	args = append(args, c, p)

	if _, err := os.Stat(p); err != nil {
		err = os.Mkdir(p, 0777)
		if err != nil {
			return err
		}
	}

	cmd := exec.Command(GocryptfsBinary, args...)
	if showOutput {
		// The Go test logic waits for our stdout to close, and when we share
		// it with the subprocess, it will wait for it to close it as well.
		// Use an intermediate pipe so the tests do not hang when unmouting
		// fails.
		pr, pw, err := os.Pipe()
		if err != nil {
			return err
		}
		// We can close the fd after cmd.Run() has executed
		defer pw.Close()
		cmd.Stderr = pw
		cmd.Stdout = pw
		go func() {
			io.Copy(os.Stdout, pr)
			pr.Close()
		}()
	}

	// Two things can happen:
	// 1) The mount fails and the process exits
	// 2) The mount succeeds and the process sends us USR1
	chanExit := make(chan error, 1)
	chanUsr1 := make(chan os.Signal, 1)
	signal.Notify(chanUsr1, syscall.SIGUSR1)

	// Start the process and save the PID
	err := cmd.Start()
	if err != nil {
		return err
	}
	pid := cmd.Process.Pid

	// Wait for exit or usr1
	go func() {
		chanExit <- cmd.Wait()
	}()
	select {
	case err := <-chanExit:
		return err
	case <-chanUsr1:
		// noop
	case <-time.After(1 * time.Second):
		log.Panicf("Timeout waiting for process %d", pid)
	}

	// Save PID and open FDs
	MountInfo[p] = mountInfo{pid, ListFds(pid)}
	return nil
}

// MountOrExit calls Mount() and exits on failure.
func MountOrExit(c string, p string, extraArgs ...string) {
	err := Mount(c, p, true, extraArgs...)
	if err != nil {
		fmt.Printf("mount failed: %v\n", err)
		os.Exit(1)
	}
}

// MountOrFatal calls Mount() and calls t.Fatal() on failure.
func MountOrFatal(t *testing.T, c string, p string, extraArgs ...string) {
	err := Mount(c, p, true, extraArgs...)
	if err != nil {
		t.Fatal(fmt.Errorf("mount failed: %v", err))
	}
}

// UnmountPanic tries to umount "dir" and panics on error.
func UnmountPanic(dir string) {
	err := UnmountErr(dir)
	if err != nil {
		fmt.Printf("UnmountPanic: %v. Running lsof %s\n", err, dir)
		cmd := exec.Command("lsof", dir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
		panic("UnmountPanic: unmount failed: " + err.Error())
	}
}

// UnmountErr tries to unmount "dir", retrying 10 times, and returns the
// resulting error.
func UnmountErr(dir string) (err error) {
	var fdsNow []string
	pid := MountInfo[dir].pid
	fds := MountInfo[dir].fds
	if pid <= 0 {
		fmt.Printf("UnmountErr: %q was not found in MountInfo, cannot check for FD leaks\n", dir)
	}

	max := 10
	// When a new filesystem is mounted, Gnome tries to read files like
	// .xdg-volume-info, autorun.inf, .Trash.
	// If we try to unmount before Gnome is done, the unmount fails with
	// "Device or resource busy", causing spurious test failures.
	// Retry a few times to hide that problem.
	for i := 1; i <= max; i++ {
		if pid > 0 {
			fdsNow = ListFds(pid)
		}
		cmd := exec.Command(UnmountScript, "-u", dir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		if err == nil {
			if pid > 0 && len(fdsNow) > len(fds) {
				fmt.Printf("FD leak? Details:\nold=%v \nnew=%v\n", fds, fdsNow)
			}
			return nil
		}
		code := ExtractCmdExitCode(err)
		fmt.Printf("UnmountErr: got exit code %d, retrying (%d/%d)\n", code, i, max)
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// ListFds lists the open file descriptors for process "pid". Pass pid=0 for
// ourselves.
func ListFds(pid int) []string {
	// We need /proc to get the list of fds for other processes. Only exists
	// on Linux.
	if runtime.GOOS != "linux" && pid > 0 {
		return nil
	}
	// Both Linux and MacOS have /dev/fd
	dir := "/dev/fd"
	if pid > 0 {
		dir = fmt.Sprintf("/proc/%d/fd", pid)
	}
	f, err := os.Open(dir)
	if err != nil {
		log.Panic(err)
	}
	defer f.Close()
	names, err := f.Readdirnames(0)
	if err != nil {
		log.Panic(err)
	}
	for i, n := range names {
		// Note: Readdirnames filters "." and ".."
		target, _ := os.Readlink(dir + "/" + n)
		names[i] = n + "=" + target
	}
	return names
}
