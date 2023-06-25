// gocryptfs is an encrypted overlay filesystem written in Go.
// See README.md ( https://github.com/rfjakob/gocryptfs/blob/master/README.md )
// and the official website ( https://nuetzlich.net/gocryptfs/ ) for details.
package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/fido2"
	"github.com/rfjakob/gocryptfs/v2/internal/readpassword"
	"github.com/rfjakob/gocryptfs/v2/internal/speed"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const maxUserEntries = 8

// loadConfig loads the config file `args.config` and decrypts the masterkey,
// or gets via the `-masterkey` or `-zerokey` command line options, if specified.
func loadConfig(args *argContainer) (masterkey []byte, cf *configfile.ConfFile, err error) {
	// First check if the file can be read at all.
	cf, err = configfile.Load(args.config)
	if err != nil {
		tlog.Fatal.Printf("Cannot open config file: %v", err)
		return nil, nil, err
	}
	// The user may have passed the master key on the command line (probably because
	// he forgot the password).
	masterkey = handleArgsMasterkey(args)
	if masterkey != nil {
		return masterkey, cf, nil
	}
	var pw []byte
	if cf.IsFeatureFlagSet(configfile.FlagFIDO2) && args.fido2 != "" {
		var fido2Obj = cf.FIDO2[args.fido2Name]
		if fido2Obj == nil {
			tlog.Fatal.Printf("Masterkey encrypted using FIDO2 token; password not found: check your --fido2-name option")
			return nil, nil, exitcodes.NewErr("", exitcodes.Usage)
		}
		tlog.Info.Println("Retrieve pseudo user and password from FIDO2 device ", args.fido2Name, " at ", args.fido2)
		pw = fido2.Secret(args.fido2, fido2Obj.CredentialID, fido2Obj.HMACSalt)
		// overwrite user to match fido2Name
		args.user = args.fido2Name
	} else {
		pw, err = readpassword.Once([]string(args.extpass), []string(args.passfile), "")
		if err != nil {
			tlog.Fatal.Println(err)
			return nil, nil, exitcodes.NewErr("", exitcodes.ReadPassword)
		}
	}
	tlog.Info.Println("Decrypting master key with user " + args.user)
	masterkey, err = cf.DecryptMasterKey(args.user, pw)
	for i := range pw {
		pw[i] = 0
	}

	if err != nil {
		tlog.Fatal.Println(err)
		return nil, nil, err
	}
	return masterkey, cf, nil
}

// changePassword - change the password of config file "filename"
func changePassword(args *argContainer) {
	var confFile *configfile.ConfFile
	{
		var masterkey []byte
		var err error
		masterkey, confFile, err = loadConfig(args)
		if err != nil {
			exitcodes.Exit(err)
		}
		if len(masterkey) == 0 {
			log.Panic("empty masterkey")
		}
		if confFile.IsFeatureFlagSet(configfile.FlagFIDO2) {
			tlog.Fatal.Printf("Password change is not supported on FIDO2-enabled filesystems.")
			os.Exit(exitcodes.Usage)
		}
		tlog.Info.Println("Please enter your new password.")
		newPw, err := readpassword.Twice([]string(args.extpass), []string(args.passfile))
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.ReadPassword)
		}
		logN := confFile.ScryptObject.LogN()
		if args._explicitScryptn {
			logN = args.scryptn
		}
		confFile.EncryptKey(masterkey, args.user, newPw, logN)
		for i := range newPw {
			newPw[i] = 0
		}
		for i := range masterkey {
			masterkey[i] = 0
		}
		// masterkey and newPw run out of scope here
	}
	// Are we resetting the password without knowing the old one using
	// "-masterkey"?
	if args.masterkey != "" {
		bak := args.config + ".bak"
		err := os.Link(args.config, bak)
		if err != nil {
			tlog.Fatal.Printf("Could not create backup file: %v", err)
			os.Exit(exitcodes.Init)
		}
		tlog.Info.Printf(tlog.ColorGrey+
			"A copy of the old config file has been created at %q.\n"+
			"Delete it after you have verified that you can access your files with the new password."+
			tlog.ColorReset, bak)
	}
	err := confFile.WriteFile()
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.WriteConf)
	}
	tlog.Info.Printf(tlog.ColorGreen + "Password changed." + tlog.ColorReset)
}

// add user from <addUser> flag to config file "filename"
func addUser(args *argContainer) {
	var confFile *configfile.ConfFile
	{
		var masterkey []byte
		var err error
		masterkey, confFile, err = loadConfig(args)
		if err != nil {
			exitcodes.Exit(err)
		}
		if len(masterkey) == 0 {
			log.Panic("empty masterkey")
		}
		// Are we using "-masterkey"?
		if args.masterkey != "" {
			log.Panic("<addUser> is not allowed in conjunction with '-masterkey'")
		}
		if args.addUser == "" {
			log.Panic("missing argument <addUser> in addUser")
		}
		if args.addUser == args.user {
			log.Panic("<addUser> and <user> must be different")
		}
		if len(confFile.EncryptedKeys) >= maxUserEntries-1 {
			log.Panic("only ", maxUserEntries, " user/pw entries are allowed")
		}
		if _, ok := confFile.EncryptedKeys[args.addUser]; ok {
			log.Panic("User ", args.addUser, " does already exist")
		}
		tlog.Info.Println("Please enter the password for new user ", args.addUser, ".")
		newPw, err := readpassword.Twice([]string(args.extpass), []string(args.passfile))
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.ReadPassword)
		}
		logN := confFile.ScryptObject.LogN()
		if args._explicitScryptn {
			logN = args.scryptn
		}
		confFile.EncryptKey(masterkey, args.addUser, newPw, logN)
		for i := range newPw {
			newPw[i] = 0
		}
		for i := range masterkey {
			masterkey[i] = 0
		}
		// masterkey and newPw run out of scope here
	}
	err := confFile.WriteFile()
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.WriteConf)
	}
	tlog.Info.Printf(tlog.ColorGreen+"Password set for user %v."+tlog.ColorReset, args.addUser)
}

// delete user from <deleteUser> flag from config file "filename"
func deleteUser(args *argContainer) {
	var confFile *configfile.ConfFile
	{
		var masterkey []byte
		var err error
		masterkey, confFile, err = loadConfig(args)
		if err != nil {
			exitcodes.Exit(err)
		}
		if len(masterkey) == 0 {
			log.Panic("empty masterkey")
		}
		// Are we using "-masterkey"?
		if args.masterkey != "" {
			log.Panic("<deleteUser> is not allowed in conjunction with '-masterkey'")
		}
		if args.deleteUser == "" {
			log.Panic("missing argument <deleteUser> in deleteUser")
		}
		if args.deleteUser == args.user {
			log.Panic("<deleteUser> and <user> must be different")
		}
		if len(confFile.EncryptedKeys) <= 1 {
			log.Panic("tried to delete last user")
		}
		if _, ok := confFile.EncryptedKeys[args.deleteUser]; !ok {
			log.Panic("User ", args.deleteUser, " does not exist")
		}
		delete(confFile.EncryptedKeys, args.deleteUser)
		for i := range masterkey {
			masterkey[i] = 0
		}
		// masterkey run out of scope here
	}
	err := confFile.WriteFile()
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.WriteConf)
	}
	tlog.Info.Printf(tlog.ColorGreen+"User %v."+tlog.ColorReset, args.deleteUser)
	tlog.Info.Printf(tlog.ColorYellow +
		"Warning: Deleting a user is unsafe - as the deleted user could have retrieved the masterkey or copied gocryptfs.conf already" +
		tlog.ColorReset)
}

// add fido2 device from <add-fido2> flag to config file "filename"
func addFido2(args *argContainer) {
	var confFile *configfile.ConfFile
	{
		var masterkey []byte
		var err error
		masterkey, confFile, err = loadConfig(args)
		if err != nil {
			exitcodes.Exit(err)
		}
		if len(masterkey) == 0 {
			log.Panic("empty masterkey")
		}
		// Are we using "-masterkey"?
		if args.masterkey != "" {
			log.Panic("<addFido2> is not allowed in conjunction with '-masterkey'")
		}
		if args.addFido2Device == "" {
			log.Panic("missing argument <addFido2Device> in addFido2")
		}
		if args.addFido2 == "" {
			log.Panic("missing argument <addFido2> in addFido2")
		}
		if args.addFido2 == args.fido2 {
			log.Panic("<addFido2> and <fido2> must be different")
		}
		if len(confFile.EncryptedKeys) >= maxUserEntries-1 {
			log.Panic("only ", maxUserEntries, " user/pw entries are allowed (including fido2 devices)")
		}
		if _, ok := confFile.EncryptedKeys[args.addFido2]; ok {
			log.Panic("User/Device ", args.addFido2, " does already exist")
		}
		tlog.Info.Println("Adding new FIDO2 device ", args.addFido2, " at ", args.addFido2Device)
		confFile.SetFeatureFlagFIDO2()
		/*
			newPw, err := readpassword.Twice([]string(args.extpass), []string(args.passfile))
			if err != nil {
				tlog.Fatal.Println(err)
				os.Exit(exitcodes.ReadPassword)
			}
			logN := confFile.ScryptObject.LogN()
			if args._explicitScryptn {
				logN = args.scryptn
			}
			confFile.EncryptKey(masterkey, args.addUser, newPw, logN)
			for i := range newPw {
				newPw[i] = 0
			}
		*/
		params := configfile.FIDO2Params{
			CredentialID: fido2.Register(args.addFido2Device, args.addFido2),
			HMACSalt:     cryptocore.RandBytes(32),
		}
		password := fido2.Secret(args.addFido2Device, params.CredentialID, params.HMACSalt)
		// overwrite addUser to match addFido2
		args.addUser = args.addFido2

		logN := confFile.ScryptObject.LogN()
		if args._explicitScryptn {
			logN = args.scryptn
		}
		confFile.EncryptKey(masterkey, args.addUser, password, logN)
		if confFile.FIDO2 == nil {
			confFile.FIDO2 = make(configfile.FIDO2ParamsMap)
		}
		if _, ok := confFile.FIDO2[args.addFido2]; ok {
			log.Panic("FIDO2 device ", args.addFido2, " does already exist")
		}
		confFile.FIDO2[args.addFido2] = &params

		for i := range masterkey {
			masterkey[i] = 0
		}
		for i := range password {
			password[i] = 0
		}
		// masterkey and password run out of scope here
	}
	err := confFile.WriteFile()
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.WriteConf)
	}
	tlog.Info.Printf(tlog.ColorGreen+"Password set for user %v."+tlog.ColorReset, args.addUser)
}

func main() {
	mxp := runtime.GOMAXPROCS(0)
	if mxp < 4 && os.Getenv("GOMAXPROCS") == "" {
		// On a 2-core machine, setting maxprocs to 4 gives 10% better performance.
		// But don't override an explicitly set GOMAXPROCS env variable.
		runtime.GOMAXPROCS(4)
	}
	// mount(1) unsets PATH. Since exec.Command does not handle this case, we set
	// PATH to a default value if it's empty or unset.
	if os.Getenv("PATH") == "" {
		os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	}
	// Show microseconds in go-fuse debug output (-fusedebug)
	log.SetFlags(log.Lmicroseconds)
	var err error
	// Parse all command-line options (i.e. arguments starting with "-")
	// into "args". Path arguments are parsed below.
	args := parseCliOpts(os.Args)
	// Fork a child into the background if "-fg" is not set AND we are mounting
	// a filesystem. The child will do all the work.
	if !args.fg && flagSet.NArg() == 2 {
		ret := forkChild()
		os.Exit(ret)
	}
	if args.debug {
		tlog.Debug.Enabled = true
	}
	tlog.Debug.Printf("cli args: %q", os.Args)
	// "-v"
	if args.version {
		tlog.Debug.Printf("openssl=%v\n", args.openssl)
		tlog.Debug.Printf("on-disk format %d\n", contentenc.CurrentVersion)
		printVersion()
		os.Exit(0)
	}
	// "-hh"
	if args.hh {
		helpLong()
		os.Exit(0)
	}
	// "-speed"
	if args.speed {
		printVersion()
		speed.Run()
		os.Exit(0)
	}
	if args.wpanic {
		tlog.Warn.Wpanic = true
		tlog.Debug.Printf("Panicking on warnings")
	}
	// Every operation below requires CIPHERDIR. Exit if we don't have it.
	if flagSet.NArg() == 0 {
		if flagSet.NFlag() == 0 {
			// Naked call to "gocryptfs". Just print the help text.
			helpShort()
		} else {
			// The user has passed some flags, but CIPHERDIR is missing. State
			// what is wrong.
			tlog.Fatal.Printf("CIPHERDIR argument is missing")
		}
		os.Exit(exitcodes.Usage)
	}
	// Check that CIPHERDIR exists
	args.cipherdir, _ = filepath.Abs(flagSet.Arg(0))
	err = isDir(args.cipherdir)
	if err != nil {
		tlog.Fatal.Printf("Invalid cipherdir: %v", err)
		os.Exit(exitcodes.CipherDir)
	}
	// "-q"
	if args.quiet {
		tlog.Info.Enabled = false
	}
	// "-reverse" implies "-aessiv"
	if args.reverse {
		args.aessiv = true
	} else {
		if args.exclude != nil {
			tlog.Fatal.Printf("-exclude only works in reverse mode")
			os.Exit(exitcodes.ExcludeError)
		}
	}
	// "-config"
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
	// "-force_owner"
	if args.force_owner != "" {
		var uidNum, gidNum int64
		ownerPieces := strings.SplitN(args.force_owner, ":", 2)
		if len(ownerPieces) != 2 {
			tlog.Fatal.Printf("force_owner must be in form UID:GID")
			os.Exit(exitcodes.Usage)
		}
		uidNum, err = strconv.ParseInt(ownerPieces[0], 0, 32)
		if err != nil || uidNum < 0 {
			tlog.Fatal.Printf("force_owner: Unable to parse UID %v as positive integer", ownerPieces[0])
			os.Exit(exitcodes.Usage)
		}
		gidNum, err = strconv.ParseInt(ownerPieces[1], 0, 32)
		if err != nil || gidNum < 0 {
			tlog.Fatal.Printf("force_owner: Unable to parse GID %v as positive integer", ownerPieces[1])
			os.Exit(exitcodes.Usage)
		}
		args._forceOwner = &fuse.Owner{Uid: uint32(uidNum), Gid: uint32(gidNum)}
	}
	// "-cpuprofile"
	if args.cpuprofile != "" {
		onExitFunc := setupCpuprofile(args.cpuprofile)
		defer onExitFunc()
	}
	// "-memprofile"
	if args.memprofile != "" {
		onExitFunc := setupMemprofile(args.memprofile)
		defer onExitFunc()
	}
	// "-trace"
	if args.trace != "" {
		onExitFunc := setupTrace(args.trace)
		defer onExitFunc()
	}
	if args.cpuprofile != "" || args.memprofile != "" || args.trace != "" {
		tlog.Info.Printf("Note: You must unmount gracefully, otherwise the profile file(s) will stay empty!\n")
	}
	// Operation flags
	nOps := countOpFlags(&args)
	if nOps == 0 {
		// Default operation: mount.
		if flagSet.NArg() != 2 {
			prettyArgs := prettyArgs()
			tlog.Info.Printf("Wrong number of arguments (have %d, want 2). You passed: %s",
				flagSet.NArg(), prettyArgs)
			tlog.Fatal.Printf("Usage: %s [OPTIONS] CIPHERDIR MOUNTPOINT [-o COMMA-SEPARATED-OPTIONS]", tlog.ProgramName)
			os.Exit(exitcodes.Usage)
		}
		doMount(&args)
		// Don't call os.Exit to give deferred functions a chance to run
		return
	}
	if nOps > 1 {
		tlog.Fatal.Printf("At most one of -info, -init, -passwd, -fsck, --add-user, --delete-user, --add-fido2, --delete-fido2 is allowed")
		os.Exit(exitcodes.Usage)
	}
	if flagSet.NArg() != 1 {
		tlog.Fatal.Printf("The options -info, -init, -passwd, -fsck, --add-user, --delete-user, --add-fido2, --delete-fido2 take exactly one argument, %d given",
			flagSet.NArg())
		os.Exit(exitcodes.Usage)
	}
	// "-info"
	if args.info {
		info(args.config)
		os.Exit(0)
	}
	// "-init"
	if args.init {
		initDir(&args)
		os.Exit(0)
	}
	// "-passwd"
	if args.passwd {
		changePassword(&args)
		os.Exit(0)
	}
	// "-fsck"
	if args.fsck {
		code := fsck(&args)
		os.Exit(code)
	}
	// TODO tp
	if args.addUser != "" {
		addUser(&args)
		os.Exit(0)
	}
	if args.deleteUser != "" {
		deleteUser(&args)
		os.Exit(0)
	}
	if args.addFido2 != "" {
		addFido2(&args)
		os.Exit(0)
	}
	if args.deleteFido2 != "" {
		tlog.Fatal.Printf("not implemented")
		os.Exit(0)
	}
	tlog.Fatal.Printf("parsing command line failed")
	os.Exit(0)
}
