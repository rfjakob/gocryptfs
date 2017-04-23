package main

import (
	"encoding/json"
	"io/ioutil"
	"log/syslog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/ctlsock"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/internal/fusefrontend_reverse"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// doMount mounts an encrypted directory.
// Called from main.
func doMount(args *argContainer) int {
	// Check mountpoint
	var err error
	args.mountpoint, err = filepath.Abs(flagSet.Arg(1))
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(ErrExitMountPoint)
	}
	// We cannot mount "/home/user/.cipher" at "/home/user" because the mount
	// will hide ".cipher" also for us.
	if args.cipherdir == args.mountpoint || strings.HasPrefix(args.cipherdir, args.mountpoint+"/") {
		tlog.Fatal.Printf("Mountpoint %q would shadow cipherdir %q, this is not supported",
			args.mountpoint, args.cipherdir)
		os.Exit(ErrExitMountPoint)
	}
	if args.nonempty {
		err = checkDir(args.mountpoint)
	} else {
		err = checkDirEmpty(args.mountpoint)
	}
	if err != nil {
		tlog.Fatal.Printf("Invalid mountpoint: %v", err)
		os.Exit(ErrExitMountPoint)
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
			os.Exit(ErrExitMount)
		}
		args._ctlsockFd = sock
		// Close also deletes the socket file
		defer func() {
			err = sock.Close()
			if err != nil {
				tlog.Warn.Print(err)
			}
		}()
	}
	// Get master key (may prompt for the password)
	var masterkey []byte
	var confFile *configfile.ConfFile
	if args.masterkey != "" {
		// "-masterkey"
		masterkey = parseMasterKey(args.masterkey)
	} else if args.zerokey {
		// "-zerokey"
		tlog.Info.Printf("Using all-zero dummy master key.")
		tlog.Info.Printf(tlog.ColorYellow +
			"ZEROKEY MODE PROVIDES NO SECURITY AT ALL AND SHOULD ONLY BE USED FOR TESTING." +
			tlog.ColorReset)
		masterkey = make([]byte, cryptocore.KeyLen)
	} else {
		// Load master key from config file
		// Prompts the user for the password
		masterkey, confFile, err = loadConfig(args)
		if err != nil {
			if args._ctlsockFd != nil {
				// Close the socket file (which also deletes it)
				args._ctlsockFd.Close()
			}
			exitcodes.Exit(err)
		}
		readpassword.CheckTrailingGarbage()
		printMasterKey(masterkey)
	}
	// We cannot use JSON for pretty-printing as the fields are unexported
	tlog.Debug.Printf("cli args: %#v", args)
	// Initialize FUSE server
	srv := initFuseFrontend(masterkey, args, confFile)
	tlog.Info.Println(tlog.ColorGreen + "Filesystem mounted and ready." + tlog.ColorReset)
	var paniclog *os.File
	// We have been forked into the background, as evidenced by the set
	// "notifypid".
	if args.notifypid > 0 {
		// Chdir to the root directory so we don't block unmounting the CWD
		os.Chdir("/")
		// Switch to syslog
		if !args.nosyslog {
			paniclog, err = ioutil.TempFile("", "gocryptfs_paniclog.")
			if err != nil {
				tlog.Fatal.Printf("Failed to create gocryptfs_paniclog: %v", err)
				os.Exit(ErrExitMount)
			}
			// Switch all of our logs and the generic logger to syslog
			tlog.Info.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_INFO)
			tlog.Debug.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_DEBUG)
			tlog.Warn.SwitchToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
			tlog.SwitchLoggerToSyslog(syslog.LOG_USER | syslog.LOG_WARNING)
			// Daemons should close all fds (and we don't want to get killed by
			// SIGPIPE if any of those get closed on the other end)
			os.Stdin.Close()
			// Redirect stdout and stderr to /tmp/gocryptfs_paniclog.NNNNNN
			// instead of closing them so users have a chance to get the
			// backtrace on a panic.
			// https://github.com/golang/go/issues/325#issuecomment-66049178
			syscall.Dup2(int(paniclog.Fd()), 1)
			syscall.Dup2(int(paniclog.Fd()), 2)
			// No need for the extra FD anymore, we have it saved in Stderr
			paniclog.Close()
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
	// Wait for SIGINT in the background and unmount ourselves if we get it.
	// This prevents a dangling "Transport endpoint is not connected"
	// mountpoint if the user hits CTRL-C.
	handleSigint(srv, args.mountpoint)
	// Jump into server loop. Returns when it gets an umount request from the kernel.
	srv.Serve()
	// Delete empty paniclogs
	if paniclog != nil {
		// The paniclog FD is saved in Stderr
		fi, err := os.Stderr.Stat()
		if err != nil {
			tlog.Warn.Printf("paniclog fstat error: %v", err)
		} else if fi.Size() > 0 {
			tlog.Warn.Printf("paniclog at %q is not empty (size %d). Not deleting it.",
				paniclog.Name(), fi.Size())
		} else {
			syscall.Unlink(paniclog.Name())
		}
	}
	return 0
}

// initFuseFrontend - initialize gocryptfs/fusefrontend
// Calls os.Exit on errors
func initFuseFrontend(key []byte, args *argContainer, confFile *configfile.ConfFile) *fuse.Server {
	// Reconciliate CLI and config file arguments into a fusefrontend.Args struct
	// that is passed to the filesystem implementation
	cryptoBackend := cryptocore.BackendGoGCM
	if args.openssl {
		cryptoBackend = cryptocore.BackendOpenSSL
	}
	if args.aessiv {
		cryptoBackend = cryptocore.BackendAESSIV
	}
	frontendArgs := fusefrontend.Args{
		Cipherdir:      args.cipherdir,
		Masterkey:      key,
		PlaintextNames: args.plaintextnames,
		LongNames:      args.longnames,
		CryptoBackend:  cryptoBackend,
		ConfigCustom:   args._configCustom,
		Raw64:          args.raw64,
		NoPrealloc:     args.noprealloc,
		HKDF:           args.hkdf,
		SerializeReads: args.serialize_reads,
		ForceDecode:    args.forcedecode,
	}
	// confFile is nil when "-zerokey" or "-masterkey" was used
	if confFile != nil {
		// Settings from the config file override command line args
		frontendArgs.PlaintextNames = confFile.IsFeatureFlagSet(configfile.FlagPlaintextNames)
		frontendArgs.Raw64 = confFile.IsFeatureFlagSet(configfile.FlagRaw64)
		frontendArgs.HKDF = confFile.IsFeatureFlagSet(configfile.FlagHKDF)
		if confFile.IsFeatureFlagSet(configfile.FlagAESSIV) {
			frontendArgs.CryptoBackend = cryptocore.BackendAESSIV
		} else if args.reverse {
			tlog.Fatal.Printf("AES-SIV is required by reverse mode, but not enabled in the config file")
			os.Exit(ErrExitUsage)
		}
	}
	// If allow_other is set and we run as root, try to give newly created files to
	// the right user.
	if args.allow_other && os.Getuid() == 0 {
		frontendArgs.PreserveOwner = true
	}
	jsonBytes, _ := json.MarshalIndent(frontendArgs, "", "\t")
	tlog.Debug.Printf("frontendArgs: %s", string(jsonBytes))
	var finalFs pathfs.FileSystem
	var ctlSockBackend ctlsock.Interface
	if args.reverse {
		fs := fusefrontend_reverse.NewFS(frontendArgs)
		finalFs = fs
		ctlSockBackend = fs
	} else {
		fs := fusefrontend.NewFS(frontendArgs)
		finalFs = fs
		ctlSockBackend = fs
	}
	// We have opened the socket early so that we cannot fail here after
	// asking the user for the password
	if args._ctlsockFd != nil {
		go ctlsock.Serve(args._ctlsockFd, ctlSockBackend)
	}
	pathFsOpts := &pathfs.PathNodeFsOptions{ClientInodes: true}
	pathFs := pathfs.NewPathNodeFs(finalFs, pathFsOpts)
	fuseOpts := &nodefs.Options{
		// These options are to be compatible with libfuse defaults,
		// making benchmarking easier.
		NegativeTimeout: time.Second,
		AttrTimeout:     time.Second,
		EntryTimeout:    time.Second,
	}
	conn := nodefs.NewFileSystemConnector(pathFs.Root(), fuseOpts)
	var mOpts fuse.MountOptions
	mOpts.AllowOther = false
	if args.allow_other {
		tlog.Info.Printf(tlog.ColorYellow + "The option \"-allow_other\" is set. Make sure the file " +
			"permissions protect your data from unwanted access." + tlog.ColorReset)
		mOpts.AllowOther = true
		// Make the kernel check the file permissions for us
		mOpts.Options = append(mOpts.Options, "default_permissions")
	}
	if args.nonempty {
		mOpts.Options = append(mOpts.Options, "nonempty")
	}
	// Set values shown in "df -T" and friends
	// First column, "Filesystem"
	fsname := args.cipherdir
	if args.fsname != "" {
		fsname = args.fsname
	}
	mOpts.Options = append(mOpts.Options, "fsname="+fsname)
	// Second column, "Type", will be shown as "fuse." + Name
	mOpts.Name = "gocryptfs"
	if args.reverse {
		mOpts.Name += "-reverse"
	}
	// The kernel enforces read-only operation, we just have to pass "ro".
	// Reverse mounts are always read-only.
	if args.ro || args.reverse {
		mOpts.Options = append(mOpts.Options, "ro")
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
		tlog.Fatal.Printf("Mount failed: %v", err)
		os.Exit(ErrExitMount)
	}
	srv.SetDebug(args.fusedebug)

	// All FUSE file and directory create calls carry explicit permission
	// information. We need an unrestricted umask to create the files and
	// directories with the requested permissions.
	syscall.Umask(0000)

	return srv
}

func handleSigint(srv *fuse.Server, mountpoint string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		err := srv.Unmount()
		if err != nil {
			tlog.Warn.Print(err)
			if runtime.GOOS == "linux" {
				// MacOSX does not support lazy unmount
				tlog.Info.Printf("Trying lazy unmount")
				cmd := exec.Command("fusermount", "-u", "-z", mountpoint)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}
		}
		os.Exit(1)
	}()
}
