package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend_reverse"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/openfiletable"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// doMount mounts an encrypted directory.
// Called from main.
func doMount(args *argContainer) {
	// Check mountpoint
	var err error
	args.mountpoint, err = filepath.Abs(flagSet.Arg(1))
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(exitcodes.MountPoint)
	}
	// We cannot mount "/home/user/.cipher" at "/home/user" because the mount
	// will hide ".cipher" also for us.
	if args.cipherdir == args.mountpoint || strings.HasPrefix(args.cipherdir, args.mountpoint+"/") {
		tlog.Fatal.Printf("Mountpoint %q would shadow cipherdir %q, this is not supported",
			args.mountpoint, args.cipherdir)
		os.Exit(exitcodes.MountPoint)
	}
	// Reverse-mounting "/foo" at "/foo/mnt" means we would be recursively
	// encrypting ourselves.
	if strings.HasPrefix(args.mountpoint, args.cipherdir+"/") {
		tlog.Fatal.Printf("Mountpoint %q is contained in cipherdir %q, this is not supported",
			args.mountpoint, args.cipherdir)
		os.Exit(exitcodes.MountPoint)
	}
	if args.nonempty {
		err = isDir(args.mountpoint)
	} else {
		err = isEmptyDir(args.mountpoint)
		// OSXFuse will create the mountpoint for us ( https://github.com/rfjakob/gocryptfs/issues/194 )
		if runtime.GOOS == "darwin" && os.IsNotExist(err) {
			tlog.Info.Printf("Mountpoint %q does not exist, but should be created by OSXFuse",
				args.mountpoint)
			err = nil
		}
	}
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(exitcodes.MountPoint)
	}
	// Open control socket early so we can error out before asking the user
	// for the password
	if args.ctlsock != "" {
		// We must use an absolute path because we cd to / when daemonizing.
		// This messes up the delete-on-close logic in the unix socket object.
		args.ctlsock, _ = filepath.Abs(args.ctlsock)
		var sock net.Listener
		sock, err = net.Listen("unix", args.ctlsock)
		if err != nil {
			tlog.Fatal.Printf("ctlsock: %v", err)
			os.Exit(exitcodes.CtlSock)
		}
		args._ctlsockFd = sock
		// Close also deletes the socket file
		defer func() {
			err = sock.Close()
			if err != nil {
				tlog.Warn.Printf("ctlsock close: %v", err)
			}
		}()
	}
	// Preallocation on Btrfs is broken ( https://github.com/rfjakob/gocryptfs/issues/395 )
	// and slow ( https://github.com/rfjakob/gocryptfs/issues/63 ).
	if !args.noprealloc {
		// darwin does not have unix.BTRFS_SUPER_MAGIC, so we define it here
		const BTRFS_SUPER_MAGIC = 0x9123683e
		var st unix.Statfs_t
		err = unix.Statfs(args.cipherdir, &st)
		// Cast to uint32 avoids compile error on arm: "constant 2435016766 overflows int32"
		if err == nil && uint32(st.Type) == BTRFS_SUPER_MAGIC {
			tlog.Info.Printf(tlog.ColorYellow +
				"Btrfs detected, forcing -noprealloc. See https://github.com/rfjakob/gocryptfs/issues/395 for why." +
				tlog.ColorReset)
			args.noprealloc = true
		}
	}
	// We cannot use JSON for pretty-printing as the fields are unexported
	tlog.Debug.Printf("cli args: %#v", args)
	// Initialize gocryptfs (read config file, ask for password, ...)
	fs, wipeKeys := initFuseFrontend(args)
	// Initialize go-fuse FUSE server
	srv := initGoFuse(fs, args)
	// Try to wipe secret keys from memory after unmount
	defer wipeKeys()

	tlog.Info.Println(tlog.ColorGreen + "Filesystem mounted and ready." + tlog.ColorReset)
	// We have been forked into the background, as evidenced by the set
	// "notifypid".
	if args.notifypid > 0 {
		// Chdir to the root directory so we don't block unmounting the CWD
		os.Chdir("/")
		// Switch to syslog
		if !args.nosyslog {
			// Switch all of our logs and the generic logger to syslog
			tlog.Info.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_INFO)
			tlog.Debug.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_DEBUG)
			tlog.Warn.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
			tlog.Fatal.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_CRIT)
			tlog.SwitchLoggerToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
			// Daemons should redirect stdin, stdout and stderr
			redirectStdFds()
		}
		// Disconnect from the controlling terminal by creating a new session.
		// This prevents us from getting SIGINT when the user presses Ctrl-C
		// to exit a running script that has called gocryptfs.
		_, err = syscall.Setsid()
		if err != nil {
			tlog.Warn.Printf("Setsid: %v", err)
		}
		// Send SIGUSR1 to our parent
		sendUsr1(args.notifypid)
	}
	// Increase the open file limit to 4096. This is not essential, so do it after
	// we have switched to syslog and don't bother the user with warnings.
	setOpenFileLimit()
	// Wait for SIGINT in the background and unmount ourselves if we get it.
	// This prevents a dangling "Transport endpoint is not connected"
	// mountpoint if the user hits CTRL-C.
	handleSigint(srv, args.mountpoint)
	// Return memory that was allocated for scrypt (64M by default!) and other
	// stuff that is no longer needed to the OS
	debug.FreeOSMemory()
	// Set up autounmount, if requested.
	if args.idle > 0 && !args.reverse {
		// Not being in reverse mode means we always have a forward file system.
		fwdFs := fs.(*fusefrontend.FS)
		go idleMonitor(args.idle, fwdFs, srv, args.mountpoint)
	}
	// Jump into server loop. Returns when it gets an umount request from the kernel.
	srv.Serve()
}

// Based on the EncFS idle monitor:
// https://github.com/vgough/encfs/blob/1974b417af189a41ffae4c6feb011d2a0498e437/encfs/main.cpp#L851
// idleMonitor is a function to be run as a thread that checks for
// filesystem idleness and unmounts if we've been idle for long enough.
const checksDuringTimeoutPeriod = 4

func idleMonitor(idleTimeout time.Duration, fs *fusefrontend.FS, srv *fuse.Server, mountpoint string) {
	sleepTimeBetweenChecks := contentenc.MinUint64(
		uint64(idleTimeout/checksDuringTimeoutPeriod),
		uint64(2*time.Minute))
	timeoutCycles := int(math.Ceil(float64(idleTimeout) / float64(sleepTimeBetweenChecks)))
	idleCount := 0
	for {
		// Atomically check whether the flag is 0 and reset it to 1 if so.
		isIdle := !atomic.CompareAndSwapUint32(&fs.IsIdle, 0, 1)
		// Any form of current or recent access resets the idle counter.
		openFileCount := openfiletable.CountOpenFiles()
		if !isIdle || openFileCount > 0 {
			idleCount = 0
		} else {
			idleCount++
		}
		tlog.Debug.Printf(
			"Checking for idle (isIdle = %t, open = %d): %s",
			isIdle, openFileCount, time.Now().String())
		if idleCount > 0 && idleCount%timeoutCycles == 0 {
			tlog.Info.Printf("Filesystem idle; unmounting: %s", mountpoint)
			unmount(srv, mountpoint)
		}
		time.Sleep(time.Duration(sleepTimeBetweenChecks))
	}
}

// setOpenFileLimit tries to increase the open file limit to 4096 (the default hard
// limit on Linux).
func setOpenFileLimit() {
	var lim syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	if err != nil {
		tlog.Warn.Printf("Getting RLIMIT_NOFILE failed: %v", err)
		return
	}
	if lim.Cur >= 4096 {
		return
	}
	lim.Cur = 4096
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	if err != nil {
		tlog.Warn.Printf("Setting RLIMIT_NOFILE to %+v failed: %v", lim, err)
		//         %+v output: "{Cur:4097 Max:4096}" ^
	}
}

// ctlsockFs satisfies both the pathfs.FileSystem and the ctlsock.Interface
// interfaces
type ctlsockFs interface {
	pathfs.FileSystem
	ctlsock.Interface
}

// initFuseFrontend - initialize gocryptfs/fusefrontend
// Calls os.Exit on errors
func initFuseFrontend(args *argContainer) (pfs pathfs.FileSystem, wipeKeys func()) {
	// Get master key (may prompt for the password) and read config file
	masterkey, confFile := getMasterKey(args)
	// Reconciliate CLI and config file arguments into a fusefrontend.Args struct
	// that is passed to the filesystem implementation
	cryptoBackend := cryptocore.BackendGoGCM
	if args.openssl {
		cryptoBackend = cryptocore.BackendOpenSSL
	}
	if args.aessiv {
		cryptoBackend = cryptocore.BackendAESSIV
	}
	// forceOwner implies allow_other, as documented.
	// Set this early, so args.allow_other can be relied on below this point.
	if args._forceOwner != nil {
		args.allow_other = true
	}
	frontendArgs := fusefrontend.Args{
		Cipherdir:       args.cipherdir,
		PlaintextNames:  args.plaintextnames,
		LongNames:       args.longnames,
		ConfigCustom:    args._configCustom,
		NoPrealloc:      args.noprealloc,
		SerializeReads:  args.serialize_reads,
		ForceDecode:     args.forcedecode,
		ForceOwner:      args._forceOwner,
		Exclude:         args.exclude,
		ExcludeWildcard: args.excludeWildcard,
		ExcludeFrom:     args.excludeFrom,
	}
	// confFile is nil when "-zerokey" or "-masterkey" was used
	if confFile != nil {
		// Settings from the config file override command line args
		frontendArgs.PlaintextNames = confFile.IsFeatureFlagSet(configfile.FlagPlaintextNames)
		args.raw64 = confFile.IsFeatureFlagSet(configfile.FlagRaw64)
		args.hkdf = confFile.IsFeatureFlagSet(configfile.FlagHKDF)
		if confFile.IsFeatureFlagSet(configfile.FlagAESSIV) {
			cryptoBackend = cryptocore.BackendAESSIV
		} else if args.reverse {
			tlog.Fatal.Printf("AES-SIV is required by reverse mode, but not enabled in the config file")
			os.Exit(exitcodes.Usage)
		}
	}
	// If allow_other is set and we run as root, try to give newly created files to
	// the right user.
	if args.allow_other && os.Getuid() == 0 {
		frontendArgs.PreserveOwner = true
	}
	jsonBytes, _ := json.MarshalIndent(frontendArgs, "", "\t")
	tlog.Debug.Printf("frontendArgs: %s", string(jsonBytes))

	// Init crypto backend
	cCore := cryptocore.New(masterkey, cryptoBackend, contentenc.DefaultIVBits, args.hkdf, args.forcedecode)
	cEnc := contentenc.New(cCore, contentenc.DefaultBS, args.forcedecode)
	nameTransform := nametransform.New(cCore.EMECipher, frontendArgs.LongNames, args.raw64)
	// After the crypto backend is initialized,
	// we can purge the master key from memory.
	for i := range masterkey {
		masterkey[i] = 0
	}
	masterkey = nil
	// Spawn fusefrontend
	var fs ctlsockFs
	if args.reverse {
		if cryptoBackend != cryptocore.BackendAESSIV {
			log.Panic("reverse mode must use AES-SIV, everything else is insecure")
		}
		fs = fusefrontend_reverse.NewFS(frontendArgs, cEnc, nameTransform)

	} else {
		fs = fusefrontend.NewFS(frontendArgs, cEnc, nameTransform)
	}
	// We have opened the socket early so that we cannot fail here after
	// asking the user for the password
	if args._ctlsockFd != nil {
		go ctlsock.Serve(args._ctlsockFd, fs)
	}
	return fs, func() { cCore.Wipe() }
}

func initGoFuse(fs pathfs.FileSystem, args *argContainer) *fuse.Server {
	// pathFsOpts are passed into go-fuse/pathfs
	pathFsOpts := &pathfs.PathNodeFsOptions{ClientInodes: true}
	if args.sharedstorage {
		// shared storage mode disables hard link tracking as the backing inode
		// numbers may change behind our back:
		// https://github.com/rfjakob/gocryptfs/issues/156
		pathFsOpts.ClientInodes = false
	}
	if args.reverse {
		// Reverse mode is read-only, so we don't need a working link().
		// Disable hard link tracking to avoid strange breakage on duplicate
		// inode numbers ( https://github.com/rfjakob/gocryptfs/issues/149 ).
		pathFsOpts.ClientInodes = false
	}
	pathFs := pathfs.NewPathNodeFs(fs, pathFsOpts)
	var fuseOpts *nodefs.Options
	if args.sharedstorage {
		// sharedstorage mode sets all cache timeouts to zero so changes to the
		// backing shared storage show up immediately.
		fuseOpts = &nodefs.Options{}
	} else {
		fuseOpts = &nodefs.Options{
			// These options are to be compatible with libfuse defaults,
			// making benchmarking easier.
			NegativeTimeout: time.Second,
			AttrTimeout:     time.Second,
			EntryTimeout:    time.Second,
		}
	}
	conn := nodefs.NewFileSystemConnector(pathFs.Root(), fuseOpts)
	mOpts := fuse.MountOptions{
		// Writes and reads are usually capped at 128kiB on Linux through
		// the FUSE_MAX_PAGES_PER_REQ kernel constant in fuse_i.h. Our
		// sync.Pool buffer pools are sized acc. to the default. Users may set
		// the kernel constant higher, and Synology NAS kernels are known to
		// have it >128kiB. We cannot handle more than 128kiB, so we tell
		// the kernel to limit the size explicitly.
		MaxWrite: fuse.MAX_KERNEL_WRITE,
		Options:  []string{fmt.Sprintf("max_read=%d", fuse.MAX_KERNEL_WRITE)},
	}
	if args.allow_other {
		tlog.Info.Printf(tlog.ColorYellow + "The option \"-allow_other\" is set. Make sure the file " +
			"permissions protect your data from unwanted access." + tlog.ColorReset)
		mOpts.AllowOther = true
		// Make the kernel check the file permissions for us
		mOpts.Options = append(mOpts.Options, "default_permissions")
	}
	if args.forcedecode {
		tlog.Info.Printf(tlog.ColorYellow + "THE OPTION \"-forcedecode\" IS ACTIVE. GOCRYPTFS WILL RETURN CORRUPT DATA!" +
			tlog.ColorReset)
	}
	// fusermount from libfuse 3.x removed the "nonempty" option and exits
	// with an error if it sees it. Only add it to the options on libfuse 2.x.
	if args.nonempty && haveFusermount2() {
		mOpts.Options = append(mOpts.Options, "nonempty")
	}
	// Set values shown in "df -T" and friends
	// First column, "Filesystem"
	fsname := args.cipherdir
	if args.fsname != "" {
		fsname = args.fsname
	}
	fsname2 := strings.Replace(fsname, ",", "_", -1)
	if fsname2 != fsname {
		tlog.Warn.Printf("Warning: %q will be displayed as %q in \"df -T\"", fsname, fsname2)
		fsname = fsname2
	}
	mOpts.Options = append(mOpts.Options, "fsname="+fsname)
	// Second column, "Type", will be shown as "fuse." + Name
	mOpts.Name = "gocryptfs"
	if args.reverse {
		mOpts.Name += "-reverse"
	}
	// Add a volume name if running osxfuse. Otherwise the Finder will show it as
	// something like "osxfuse Volume 0 (gocryptfs)".
	if runtime.GOOS == "darwin" {
		volname := strings.Replace(path.Base(args.mountpoint), ",", "_", -1)
		mOpts.Options = append(mOpts.Options, "volname="+volname)
	}
	// The kernel enforces read-only operation, we just have to pass "ro".
	// Reverse mounts are always read-only.
	if args.ro || args.reverse {
		mOpts.Options = append(mOpts.Options, "ro")
	} else if args.rw {
		mOpts.Options = append(mOpts.Options, "rw")
	}
	// If both "nosuid" and "suid" were passed, the safer option wins.
	if args.nosuid {
		mOpts.Options = append(mOpts.Options, "nosuid")
	} else if args.suid {
		mOpts.Options = append(mOpts.Options, "suid")
	}
	if args.nodev {
		mOpts.Options = append(mOpts.Options, "nodev")
	} else if args.dev {
		mOpts.Options = append(mOpts.Options, "dev")
	}
	if args.noexec {
		mOpts.Options = append(mOpts.Options, "noexec")
	} else if args.exec {
		mOpts.Options = append(mOpts.Options, "exec")
	}
	// Add additional mount options (if any) after the stock ones, so the user has
	// a chance to override them.
	if args.ko != "" {
		parts := strings.Split(args.ko, ",")
		tlog.Debug.Printf("Adding -ko mount options: %v", parts)
		mOpts.Options = append(mOpts.Options, parts...)
	}
	srv, err := fuse.NewServer(conn.RawFS(), args.mountpoint, &mOpts)
	if err != nil {
		tlog.Fatal.Printf("fuse.NewServer failed: %s", strings.TrimSpace(err.Error()))
		if runtime.GOOS == "darwin" {
			tlog.Info.Printf("Maybe you should run: /Library/Filesystems/osxfuse.fs/Contents/Resources/load_osxfuse")
		}
		os.Exit(exitcodes.FuseNewServer)
	}
	srv.SetDebug(args.fusedebug)

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	return srv
}

// haveFusermount2 finds out if the "fusermount" binary is from libfuse 2.x.
func haveFusermount2() bool {
	cmd := exec.Command("/bin/fusermount", "-V")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		tlog.Warn.Printf("warning: haveFusermount2: %v", err)
		return false
	}
	// libfuse 2: fusermount version: 2.9.9
	// libfuse 3: fusermount3 version: 3.9.0
	v := out.String()
	if strings.HasPrefix(v, "fusermount version") {
		return true
	}
	return false
}

func handleSigint(srv *fuse.Server, mountpoint string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		unmount(srv, mountpoint)
		os.Exit(exitcodes.SigInt)
	}()
}

func unmount(srv *fuse.Server, mountpoint string) {
	err := srv.Unmount()
	if err != nil {
		tlog.Warn.Printf("unmount: srv.Unmount returned %v", err)
		if runtime.GOOS == "linux" {
			// MacOSX does not support lazy unmount
			tlog.Info.Printf("Trying lazy unmount")
			cmd := exec.Command("fusermount", "-u", "-z", mountpoint)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
		}
	}
}
