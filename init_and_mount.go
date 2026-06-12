package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// initMountPositions holds the index of the "-init" and "-mount" tokens in the
// raw command line (os.Args).
type initMountPositions struct {
	initPos  int
	mountPos int
}

// flagTokenIndex returns the index of the first argument in osArgs that exactly
// matches one of the given flag spellings (e.g. "-init" or "--init"). It stops
// at a standalone "--", which disables option parsing. Returns -1 if not found.
func flagTokenIndex(osArgs []string, names ...string) int {
	for i, a := range osArgs {
		if a == "--" {
			return -1
		}
		for _, n := range names {
			if a == n {
				return i
			}
		}
	}
	return -1
}

// detectInitMount reports whether the command line is a combined
// "-init ... -mount ..." invocation and returns the positions of the two flags.
// ok is true only if BOTH flags are present.
func detectInitMount(osArgs []string) (pos initMountPositions, ok bool) {
	pos.initPos = flagTokenIndex(osArgs, "-init", "--init")
	pos.mountPos = flagTokenIndex(osArgs, "-mount", "--mount")
	return pos, pos.initPos >= 0 && pos.mountPos >= 0
}

// doInitAndMount processes a combined "-init ... -mount ..." command line.
//
// It builds two argument sets and runs each as if it were a separate gocryptfs
// call, so options never leak between the two phases:
//
//  1. init phase  : everything from "-init" up to (but not including) "-mount".
//  2. mount phase : a normal mount command line built by replacing the "-mount"
//     token with the cipherdir from the init phase, keeping the plaintext
//     mountpoint and all mount options that follow.
//
// The password entered during -init is reused for the mount phase. If the init
// phase fails, initDir() calls os.Exit immediately, so the mount phase is never
// reached. Returns the process exit code.
func doInitAndMount(osArgs []string, pos initMountPositions) int {
	// -init must come before -mount.
	if pos.mountPos < pos.initPos {
		tlog.Fatal.Printf("-init must come before -mount on the command line")
		return exitcodes.Usage
	}
	// Phase 1: init. Arguments are [prog, -init, CIPHERDIR, <init-options>].
	initArgs := append([]string{osArgs[0]}, osArgs[pos.initPos:pos.mountPos]...)
	cipherdir, password, initMasterkey := runInitPhase(initArgs)

	// Phase 2: mount. Replace the "-mount" token with the cipherdir from the
	// init phase to form a normal mount command line:
	//   [prog, CIPHERDIR, MOUNTPOINT, <mount-options>]
	// A bare "-masterkey" in the mount section reuses the masterkey value from
	// the init section; an explicit value must match it (see
	// resolveMountMasterkey).
	mountSection := resolveMountMasterkey(osArgs[pos.mountPos+1:], initMasterkey)
	mountArgs := append([]string{osArgs[0], cipherdir}, mountSection...)
	return runMountPhase(mountArgs, password)
}

// resolveMountMasterkey processes the "-masterkey" option found in the
// mount-section tokens of a combined "-init ... -mount ..." command line, given
// the masterkey value (raw string) that was passed to the init section.
//
//   - A bare "-masterkey" (no value) reuses initMasterkey. This requires that
//     the init section was given an explicit "-masterkey <key>"; otherwise it is
//     a fatal usage error.
//   - An explicit "-masterkey=<key>" or "-masterkey <key>" must match
//     initMasterkey. A different value is rejected so the combined call fails
//     instead of mounting with a key that does not match the freshly
//     initialized filesystem.
//
// Returns the possibly-rewritten mount-section tokens.
func resolveMountMasterkey(mountTokens []string, initMasterkey string) []string {
	out := make([]string, 0, len(mountTokens))
	for i := 0; i < len(mountTokens); i++ {
		t := mountTokens[i]
		// Stop processing options after a standalone "--".
		if t == "--" {
			out = append(out, mountTokens[i:]...)
			break
		}
		// Explicit "=" form: -masterkey=VALUE / --masterkey=VALUE.
		if v, ok := masterkeyEqValue(t); ok {
			requireMatchingMasterkey(v, initMasterkey)
			out = append(out, t)
			continue
		}
		// Bare token: -masterkey / --masterkey.
		if t == "-masterkey" || t == "--masterkey" {
			// Explicit space form "-masterkey VALUE": the next token looks like
			// a masterkey value. Keep both tokens and verify the value matches.
			if i+1 < len(mountTokens) && looksLikeMasterkeyValue(mountTokens[i+1]) {
				requireMatchingMasterkey(mountTokens[i+1], initMasterkey)
				out = append(out, t, mountTokens[i+1])
				i++
				continue
			}
			// Bare "-masterkey": reuse the init masterkey value.
			if initMasterkey == "" {
				tlog.Fatal.Printf("-masterkey in the -mount section requires -masterkey <key> in the -init section")
				os.Exit(exitcodes.Usage)
			}
			out = append(out, "-masterkey="+initMasterkey)
			continue
		}
		out = append(out, t)
	}
	return out
}

// masterkeyEqValue returns the value of a "-masterkey=VALUE" / "--masterkey=VALUE"
// token, and ok=true if tok is such a token.
func masterkeyEqValue(tok string) (value string, ok bool) {
	for _, p := range []string{"-masterkey=", "--masterkey="} {
		if strings.HasPrefix(tok, p) {
			return tok[len(p):], true
		}
	}
	return "", false
}

// looksLikeMasterkeyValue reports whether tok looks like a value accepted by
// "-masterkey": the literal "stdin", or a hex-encoded key of the expected
// length (optionally grouped with dashes). This lets us tell an explicit
// "-masterkey <key>" apart from a bare "-masterkey" followed by the mountpoint.
func looksLikeMasterkeyValue(tok string) bool {
	if tok == "stdin" {
		return true
	}
	s := strings.Replace(tok, "-", "", -1)
	if len(s) != cryptocore.KeyLen*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// requireMatchingMasterkey verifies that an explicit masterkey value given in
// the mount section matches the one given in the init section. A mismatch is a
// fatal error so the combined call fails rather than mounting with a key that
// does not match the freshly initialized filesystem.
func requireMatchingMasterkey(mountValue, initMasterkey string) {
	// Nothing to compare against, or a value we cannot compare without side
	// effects (reading stdin): leave it to the normal mount path.
	if initMasterkey == "" || mountValue == "stdin" || initMasterkey == "stdin" {
		return
	}
	norm := func(s string) string {
		return strings.ToLower(strings.Replace(s, "-", "", -1))
	}
	if norm(mountValue) != norm(initMasterkey) {
		tlog.Fatal.Printf("-masterkey value in the -mount section does not match the -masterkey value in the -init section")
		os.Exit(exitcodes.MasterKey)
	}
}

// runInitPhase parses initArgs as a standalone init call and runs initDir. It
// returns the absolute cipherdir, the password captured during init, and the
// raw masterkey value passed via "-masterkey" (empty if none was given).
// initDir calls os.Exit on any failure, satisfying "exit immediately if -init
// fails".
func runInitPhase(initArgs []string) (cipherdir string, password []byte, masterkey string) {
	args := parseCliOpts(initArgs)
	if !args.init {
		tlog.Fatal.Printf("internal error: init phase parsed without -init")
		os.Exit(exitcodes.Usage)
	}
	if args.debug {
		tlog.Debug.Enabled = true
	}
	if args.quiet {
		tlog.Info.Enabled = false
	}
	if flagSet.NArg() != 1 {
		tlog.Fatal.Printf("-init takes exactly one argument (CIPHERDIR), %d given", flagSet.NArg())
		os.Exit(exitcodes.Usage)
	}
	var err error
	args.cipherdir, err = filepath.Abs(flagSet.Arg(0))
	if err != nil {
		tlog.Fatal.Printf("Invalid cipherdir: %v", err)
		os.Exit(exitcodes.CipherDir)
	}
	// "-reverse" implies "-aessiv"
	if args.reverse {
		args.aessiv = true
	}
	// Determine the config file location, mirroring main().
	if args.config != "" {
		args.config, err = filepath.Abs(args.config)
		if err != nil {
			tlog.Fatal.Printf("Invalid \"-config\" setting: %v", err)
			os.Exit(exitcodes.Init)
		}
		tlog.Info.Printf("Using config file at custom location %s", args.config)
		args._configCustom = true
	} else if args.reverse {
		args.config = filepath.Join(args.cipherdir, configfile.ConfReverseName)
	} else {
		args.config = filepath.Join(args.cipherdir, configfile.ConfDefaultName)
	}
	// Runs the init; exits the process on failure.
	initDir(&args)
	return args.cipherdir, args._savedPassword, args.masterkey
}

// runMountPhase parses the normal mount command line and mounts the filesystem,
// reusing the password captured during init. If the mount section did not
// request "-fg", it daemonizes (forks a child that mounts in the foreground).
// In both cases the mount runs as a separate, normal gocryptfs invocation; the
// init password is handed over through the child's stdin. Returns the exit code.
func runMountPhase(mountArgs []string, password []byte) int {
	args := parseCliOpts(mountArgs)
	if flagSet.NArg() != 2 {
		tlog.Fatal.Printf("mount phase requires a MOUNTPOINT after -mount")
		return exitcodes.Usage
	}
	if args.fg {
		return execMountForeground(mountArgs, password)
	}
	return forkChildMount(mountArgs, password)
}

// selfPath returns the path to the running gocryptfs executable.
func selfPath() string {
	name := os.Args[0]
	buf := make([]byte, syscallcompat.PATH_MAX)
	n, err := syscall.Readlink("/proc/self/exe", buf)
	if err == nil {
		name = string(buf[:n])
	}
	return name
}

// forkChildMount daemonizes the mount phase. It forks a child that performs the
// mount in the foreground (a normal "gocryptfs -fg ... CIPHERDIR MOUNTPOINT"
// call) and feeds it the init password via stdin. The parent waits for SIGUSR1
// (successful mount) and then exits 0, or propagates the child's exit code on
// failure.
func forkChildMount(mountArgs []string, password []byte) int {
	name := selfPath()
	childArgs := []string{"-fg", fmt.Sprintf("-notifypid=%d", os.Getpid())}
	childArgs = append(childArgs, mountArgs[1:]...)
	c := exec.Command(name, childArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	stdin, err := c.StdinPipe()
	if err != nil {
		tlog.Fatal.Printf("forkChildMount: stdin pipe failed: %v", err)
		return exitcodes.ForkChild
	}
	exitOnUsr1()
	if err := c.Start(); err != nil {
		tlog.Fatal.Printf("forkChildMount: starting %s failed: %v", name, err)
		return exitcodes.ForkChild
	}
	// Feed the saved init password to the child. The child reads it from stdin
	// (a pipe, hence not a terminal), unless the mount section supplied its own
	// -extpass/-passfile, in which case this is simply ignored.
	writePasswordToPipe(stdin, password)
	if err := c.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if ws, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				return ws.ExitStatus()
			}
		}
		tlog.Fatal.Printf("forkChildMount: wait returned an unknown error: %v", err)
		return exitcodes.ForkChild
	}
	return 0
}

// execMountForeground replaces the current process with a normal foreground
// gocryptfs mount ("-fg" is already part of mountArgs), feeding the init
// password through a pre-filled stdin pipe. Does not return on success.
func execMountForeground(mountArgs []string, password []byte) int {
	r, w, err := os.Pipe()
	if err != nil {
		tlog.Fatal.Printf("mount: pipe failed: %v", err)
		return exitcodes.Other
	}
	// The password is small (< pipe buffer), so this write does not block.
	writePasswordToPipe(w, password)
	// Make the pipe read end our stdin (fd 0) so the new process image reads the
	// password from it.
	if err := syscallcompat.Dup3(int(r.Fd()), 0, 0); err != nil {
		tlog.Fatal.Printf("mount: dup3 failed: %v", err)
		return exitcodes.Other
	}
	name := selfPath()
	if err := syscall.Exec(name, mountArgs, os.Environ()); err != nil {
		tlog.Fatal.Printf("mount: exec failed: %v", err)
		return exitcodes.Other
	}
	return 0 // unreachable
}

// writePasswordToPipe writes the password followed by a newline to w, closes w,
// and wipes the password from memory.
func writePasswordToPipe(w io.WriteCloser, password []byte) {
	w.Write(password)
	w.Write([]byte("\n"))
	w.Close()
	for i := range password {
		password[i] = 0
	}
}
