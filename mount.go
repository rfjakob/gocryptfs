package main

import (
	"bytes"
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

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend_reverse"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/openfiletable"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// AfterUnmount is called after the filesystem has been unmounted.
// This can be used for cleanup and printing statistics.
type AfterUnmounter interface {
	AfterUnmount()
}

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
	} else if strings.HasPrefix(args.mountpoint, "/dev/fd/") {
		// Magic fuse fd syntax, do nothing and let go-fuse figure it out.
		//
		// See https://github.com/libfuse/libfuse/commit/64e11073b9347fcf9c6d1eea143763ba9e946f70
		// and `drop_privileges` in `man mount.fuse3` for background.
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
	// Initialize gocryptfs (read config file, ask for password, ...)
	fs, wipeKeys := initFuseFrontend(args)
	// Try to wipe secret keys from memory after unmount
	defer wipeKeys()
	// Initialize go-fuse FUSE server
	srv := initGoFuse(fs, args)
	if x, ok := fs.(AfterUnmounter); ok {
		defer x.AfterUnmount()
	}

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
			tlog.SwitchLoggerToSyslog()
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
		fwdFs := fs.(*fusefrontend.RootNode)
		go idleMonitor(args.idle, fwdFs, srv, args.mountpoint)
	}
	// Wait for unmount.
	srv.Wait()
}

// Based on the EncFS idle monitor:
// https://github.com/vgough/encfs/blob/1974b417af189a41ffae4c6feb011d2a0498e437/encfs/main.cpp#L851
// idleMonitor is a function to be run as a thread that checks for
// filesystem idleness and unmounts if we've been idle for long enough.
const checksDuringTimeoutPeriod = 4

func idleMonitor(idleTimeout time.Duration, fs *fusefrontend.RootNode, srv *fuse.Server, mountpoint string) {
	// sleepNs is the sleep time between checks, in nanoseconds.
	sleepNs := contentenc.MinUint64(
		uint64(idleTimeout/checksDuringTimeoutPeriod),
		uint64(2*time.Minute))
	timeoutCycles := int(math.Ceil(float64(idleTimeout) / float64(sleepNs)))
	idleCount := 0
	idleTime := func() time.Duration {
		return time.Duration(sleepNs * uint64(idleCount))
	}
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
			"idleMonitor: idle for %v (idleCount = %d, isIdle = %t, open = %d)",
			idleTime(), idleCount, isIdle, openFileCount)
		if idleCount > 0 && idleCount%timeoutCycles == 0 {
			tlog.Info.Printf("idleMonitor: filesystem idle; unmounting: %s", mountpoint)
			err := srv.Unmount()
			if err != nil {
				// We get "Device or resource busy" when a process has its
				// working directory on the mount. Log the event at Info level
				// so the user finds out why their filesystem does not get
				// unmounted.
				tlog.Info.Printf("idleMonitor: unmount failed: %v. Resetting idle time.", err)
				idleCount = 0
			}
		}
		time.Sleep(time.Duration(sleepNs))
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

// initFuseFrontend - initialize gocryptfs/internal/fusefrontend
// Calls os.Exit on errors
func initFuseFrontend(args *argContainer) (rootNode fs.InodeEmbedder, wipeKeys func()) {
	var err error
	var confFile *configfile.ConfFile
	// Get the masterkey from the command line if it was specified
	masterkey := handleArgsMasterkey(args)
	// Otherwise, load masterkey from config file (normal operation).
	// Prompts the user for the password.
	if masterkey == nil {
		masterkey, confFile, err = loadConfig(args)
		if err != nil {
			if args._ctlsockFd != nil {
				// Close the socket file (which also deletes it)
				args._ctlsockFd.Close()
			}
			exitcodes.Exit(err)
		}
	}
	// Reconciliate CLI and config file arguments into a fusefrontend.Args struct
	// that is passed to the filesystem implementation
	cryptoBackend := cryptocore.BackendGoGCM
	IVBits := contentenc.DefaultIVBits
	if args.openssl {
		cryptoBackend = cryptocore.BackendOpenSSL
	}
	if args.aessiv {
		cryptoBackend = cryptocore.BackendAESSIV
	}
	if args.xchacha {
		if args.openssl {
			cryptoBackend = cryptocore.BackendXChaCha20Poly1305OpenSSL
		} else {
			cryptoBackend = cryptocore.BackendXChaCha20Poly1305
		}
		IVBits = chacha20poly1305.NonceSizeX * 8
	}
	// forceOwner implies allow_other, as documented.
	// Set this early, so args.allow_other can be relied on below this point.
	if args._forceOwner != nil {
		args.allow_other = true
	}
	frontendArgs := fusefrontend.Args{
		Cipherdir:          args.cipherdir,
		PlaintextNames:     args.plaintextnames,
		LongNames:          args.longnames,
		ConfigCustom:       args._configCustom,
		NoPrealloc:         args.noprealloc,
		ForceOwner:         args._forceOwner,
		Exclude:            args.exclude,
		ExcludeWildcard:    args.excludeWildcard,
		ExcludeFrom:        args.excludeFrom,
		Suid:               args.suid,
		KernelCache:        args.kernel_cache,
		SharedStorage:      args.sharedstorage,
		OneFileSystem:      args.one_file_system,
		DeterministicNames: args.deterministic_names,
	}
	// confFile is nil when "-zerokey" or "-masterkey" was used
	if confFile != nil {
		// Settings from the config file override command line args
		frontendArgs.PlaintextNames = confFile.IsFeatureFlagSet(configfile.FlagPlaintextNames)
		frontendArgs.DeterministicNames = !confFile.IsFeatureFlagSet(configfile.FlagDirIV)
		// Things that don't have to be in frontendArgs are only in args
		args.longnamemax = confFile.LongNameMax
		args.raw64 = confFile.IsFeatureFlagSet(configfile.FlagRaw64)
		args.hkdf = confFile.IsFeatureFlagSet(configfile.FlagHKDF)
		// Note: this will always return the non-openssl variant
		cryptoBackend, err = confFile.ContentEncryption()
		if err != nil {
			tlog.Fatal.Printf("%v", err)
			os.Exit(exitcodes.DeprecatedFS)
		}
		IVBits = cryptoBackend.NonceSize * 8
		if cryptoBackend != cryptocore.BackendAESSIV && args.reverse {
			tlog.Fatal.Printf("AES-SIV is required by reverse mode, but not enabled in the config file")
			os.Exit(exitcodes.Usage)
		}
		// Upgrade to OpenSSL variant if requested
		if args.openssl {
			switch cryptoBackend {
			case cryptocore.BackendGoGCM:
				cryptoBackend = cryptocore.BackendOpenSSL
			case cryptocore.BackendXChaCha20Poly1305:
				cryptoBackend = cryptocore.BackendXChaCha20Poly1305OpenSSL
			}
		}
	}
	// If allow_other is set and we run as root, try to give newly created files to
	// the right user.
	if args.allow_other && os.Getuid() == 0 {
		frontendArgs.PreserveOwner = true
	}

	// Init crypto backend
	cCore := cryptocore.New(masterkey, cryptoBackend, IVBits, args.hkdf)
	cEnc := contentenc.New(cCore, contentenc.DefaultBS)
	nameTransform := nametransform.New(cCore.EMECipher, frontendArgs.LongNames, args.longnamemax,
		args.raw64, []string(args.badname), frontendArgs.DeterministicNames)
	// After the crypto backend is initialized,
	// we can purge the master key from memory.
	for i := range masterkey {
		masterkey[i] = 0
	}
	masterkey = nil
	// Spawn fusefrontend
	tlog.Debug.Printf("frontendArgs: %s", tlog.JSONDump(frontendArgs))
	if args.reverse {
		if cryptoBackend != cryptocore.BackendAESSIV {
			log.Panic("reverse mode must use AES-SIV, everything else is insecure")
		}
		rootNode = fusefrontend_reverse.NewRootNode(frontendArgs, cEnc, nameTransform)
	} else {
		rootNode = fusefrontend.NewRootNode(frontendArgs, cEnc, nameTransform)
	}
	// We have opened the socket early so that we cannot fail here after
	// asking the user for the password
	if args._ctlsockFd != nil {
		go ctlsocksrv.Serve(args._ctlsockFd, rootNode.(ctlsocksrv.Interface))
	}
	return rootNode, func() { cCore.Wipe() }
}

// initGoFuse calls into go-fuse to mount `rootNode` on `args.mountpoint`.
// The mountpoint is ready to use when the functions returns.
// On error, it calls os.Exit and does not return.
func initGoFuse(rootNode fs.InodeEmbedder, args *argContainer) *fuse.Server {
	var fuseOpts *fs.Options
	sec := time.Second
	if args.sharedstorage {
		// sharedstorage mode sets all cache timeouts to zero so changes to the
		// backing shared storage show up immediately.
		// Hard links are disabled by using automatically incrementing
		// inode numbers provided by go-fuse.
		fuseOpts = &fs.Options{
			FirstAutomaticIno: 1000,
		}
	} else {
		fuseOpts = &fs.Options{
			// These options are to be compatible with libfuse defaults,
			// making benchmarking easier.
			NegativeTimeout: &sec,
			AttrTimeout:     &sec,
			EntryTimeout:    &sec,
		}
	}
	fuseOpts.NullPermissions = true
	// Enable go-fuse warnings
	fuseOpts.Logger = log.New(os.Stderr, "go-fuse: ", log.Lmicroseconds)
	fuseOpts.MountOptions = fuse.MountOptions{
		// Writes and reads are usually capped at 128kiB on Linux through
		// the FUSE_MAX_PAGES_PER_REQ kernel constant in fuse_i.h. Our
		// sync.Pool buffer pools are sized acc. to the default. Users may set
		// the kernel constant higher, and Synology NAS kernels are known to
		// have it >128kiB. We cannot handle more than 128kiB, so we tell
		// the kernel to limit the size explicitly.
		MaxWrite: fuse.MAX_KERNEL_WRITE,
		Options:  []string{fmt.Sprintf("max_read=%d", fuse.MAX_KERNEL_WRITE)},
		Debug:    args.fusedebug,
		// The kernel usually submits multiple read requests in parallel,
		// which means we serve them in any order. Out-of-order reads are
		// expensive on some backing network filesystems
		// ( https://github.com/rfjakob/gocryptfs/issues/92 ).
		//
		// Setting SyncRead disables FUSE_CAP_ASYNC_READ. This makes the kernel
		// do everything in-order without parallelism.
		SyncRead: args.serialize_reads,
	}

	mOpts := &fuseOpts.MountOptions
	if args.allow_other {
		tlog.Info.Printf(tlog.ColorYellow + "The option \"-allow_other\" is set. Make sure the file " +
			"permissions protect your data from unwanted access." + tlog.ColorReset)
		mOpts.AllowOther = true
		// Make the kernel check the file permissions for us
		mOpts.Options = append(mOpts.Options, "default_permissions")
	}
	if args.acl {
		mOpts.EnableAcl = true
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
	// If both "nosuid" & "suid", "nodev" & "dev", etc were passed, the safer
	// option wins.
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
	srv, err := fs.Mount(args.mountpoint, rootNode, fuseOpts)
	if err != nil {
		tlog.Fatal.Printf("fs.Mount failed: %s", strings.TrimSpace(err.Error()))
		if runtime.GOOS == "darwin" {
			tlog.Info.Printf("Maybe you should run: /Library/Filesystems/osxfuse.fs/Contents/Resources/load_osxfuse")
		}
		os.Exit(exitcodes.FuseNewServer)
	}

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	return srv
}

// haveFusermount2 finds out if the "fusermount" binary is from libfuse 2.x.
func haveFusermount2() bool {
	path, err := exec.LookPath("fusermount")
	if err != nil {
		path = "/bin/fusermount"
	}
	cmd := exec.Command(path, "-V")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		tlog.Warn.Printf("warning: haveFusermount2: %v", err)
		return false
	}
	// libfuse 2: fusermount version: 2.9.9
	// libfuse 3: fusermount3 version: 3.9.0
	v := out.String()
	return strings.HasPrefix(v, "fusermount version")
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

// unmount() calls srv.Unmount(), and if that fails, calls "fusermount -u -z"
// (lazy unmount).
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
