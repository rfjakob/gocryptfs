package test_helpers

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// gocryptfs may hold up to maxCacheFds open for caching
// Keep in sync with fusefrontend.dirCacheSize
// TODO: How to share this constant without causing an import cycle?!
const maxCacheFds = 20

// Indexed by mountpoint. Initialized in doInit().
var MountInfo map[string]mountInfo

type mountInfo struct {
	// PID of the running gocryptfs process. Set by Mount().
	Pid int
	// List of open FDs of the running gocrypts process. Set by Mount().
	Fds []string
}

// Mount CIPHERDIR "c" on PLAINDIR "p"
// Creates "p" if it does not exist.
//
// Contrary to InitFS(), you MUST passt "-extpass=echo test" (or another way for
// getting the master key) explicitly.
func Mount(c string, p string, showOutput bool, extraArgs ...string) error {
	args := []string{"-q", "-wpanic", "-nosyslog", "-fg", fmt.Sprintf("-notifypid=%d", os.Getpid())}
	args = append(args, extraArgs...)
	if _, isset := os.LookupEnv("FUSEDEBUG"); isset {
		fmt.Println("FUSEDEBUG is set, enabling -fusedebug")
		args = append(args, "-fusedebug")
	}
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
	case <-time.After(2 * time.Second):
		log.Panicf("Timeout waiting for process %d", pid)
	}

	// Save PID and open FDs
	MountInfo[p] = mountInfo{pid, ListFds(pid, "")}
	return nil
}

// MountOrExit calls Mount() and exits on failure.
//
// Contrary to InitFS(), you MUST passt "-extpass=echo test" (or another way for
// getting the master key) explicitly.
func MountOrExit(c string, p string, extraArgs ...string) {
	err := Mount(c, p, true, extraArgs...)
	if err != nil {
		fmt.Printf("mount failed: %v\n", err)
		os.Exit(1)
	}
}

// MountOrFatal calls Mount() and calls t.Fatal() on failure.
// Creates plaindir `p` if it does not exist.
//
// Contrary to InitFS(), you MUST passt "-extpass=echo test" (or another way for
// getting the master key) explicitly.
func MountOrFatal(t *testing.T, c string, p string, extraArgs ...string) {
	t.Helper()

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
		cmd.Start()
		timer := time.AfterFunc(1*time.Second, func() {
			fmt.Printf("timeout!")
			cmd.Process.Kill()
		})
		cmd.Wait()
		timer.Stop()
		panic("UnmountPanic: unmount failed: " + err.Error())
	}
}

// UnmountErr tries to unmount "dir", retrying 10 times, and returns the
// resulting error.
func UnmountErr(dir string) (err error) {
	var fdsNow []string
	pid := MountInfo[dir].Pid
	fds := MountInfo[dir].Fds
	if pid <= 0 && runtime.GOOS == "linux" {
		// The FD leak check only works on Linux.
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
			for j := 1; j <= max; j++ {
				// File close on FUSE is asynchronous, closing a socket
				// when testing "-ctlsock" is as well. Wait a little and
				// hope that all close commands get through to the gocryptfs
				// process.
				fdsNow = ListFds(pid, "")
				if len(fdsNow) <= len(fds)+maxCacheFds {
					break
				}
				fmt.Printf("UnmountErr: fdsOld=%d fdsNow=%d, retrying\n", len(fds), len(fdsNow))
				time.Sleep(10 * time.Millisecond)
				fdsNow = ListFds(pid, "")
			}
		}
		cmd := exec.Command(UnmountScript, "-u", dir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		if err == nil {
			if len(fdsNow) > len(fds)+maxCacheFds {
				return fmt.Errorf("fd leak in gocryptfs process? pid=%d dir=%q, fds:\nold=%v \nnew=%v\n", pid, dir, fds, fdsNow)
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
// ourselves. Pass a prefix to ignore all paths that do not start with "prefix".
func ListFds(pid int, prefix string) []string {
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
		fmt.Printf("ListFds: %v\n", err)
		return nil
	}
	defer f.Close()
	// Note: Readdirnames filters "." and ".."
	names, err := f.Readdirnames(0)
	if err != nil {
		log.Panic(err)
	}
	var out []string
	var filtered []string
	for _, n := range names {
		fdPath := dir + "/" + n
		fi, err := os.Lstat(fdPath)
		if err != nil {
			// fd was closed in the meantime
			continue
		}
		if fi.Mode()&0400 > 0 {
			n += "r"
		}
		if fi.Mode()&0200 > 0 {
			n += "w"
		}
		target, err := os.Readlink(fdPath)
		if err != nil {
			// fd was closed in the meantime
			continue
		}
		if strings.HasPrefix(target, "pipe:") || strings.HasPrefix(target, "anon_inode:[eventpoll]") {
			// The Go runtime creates pipes on demand for splice(), which
			// creates spurious test failures. Ignore all pipes.
			// Also get rid of the "eventpoll" fd that is always there and not
			// interesting.
			filtered = append(filtered, target)
			continue
		}
		if prefix != "" && !strings.HasPrefix(target, prefix) {
			filtered = append(filtered, target)
			continue
		}
		out = append(out, n+"="+target)
	}
	out = append(out, fmt.Sprintf("(filtered: %s)", strings.Join(filtered, ", ")))
	return out
}
