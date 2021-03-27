package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/fido2"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// GitVersion is the gocryptfs version according to git, set by build.bash
var GitVersion = "[GitVersion not set - please compile using ./build.bash]"

// GitVersionFuse is the go-fuse library version, set by build.bash
var GitVersionFuse = "[GitVersionFuse not set - please compile using ./build.bash]"

// BuildDate is a date string like "2017-09-06", set by build.bash
var BuildDate = "0000-00-00"

const (
	ivLen      = contentenc.DefaultIVBits / 8
	authTagLen = cryptocore.AuthTagLen
	blockSize  = contentenc.DefaultBS + ivLen + cryptocore.AuthTagLen
	myName     = "gocryptfs-xray"
)

func errExit(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func prettyPrintHeader(h *contentenc.FileHeader, aessiv bool) {
	id := hex.EncodeToString(h.ID)
	msg := "Header: Version: %d, Id: %s"
	if aessiv {
		msg += ", assuming AES-SIV mode"
	} else {
		msg += ", assuming AES-GCM mode"
	}
	fmt.Printf(msg+"\n", h.Version, id)
}

// printVersion prints a version string like this:
// gocryptfs v1.7-32-gcf99cfd; go-fuse v1.0.0-174-g22a9cb9; 2019-05-12 go1.12 linux/amd64
func printVersion() {
	built := fmt.Sprintf("%s %s", BuildDate, runtime.Version())
	fmt.Printf("%s %s; %s %s/%s\n",
		myName, GitVersion, built,
		runtime.GOOS, runtime.GOARCH)
}

func usage() {
	printVersion()
	fmt.Printf("\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] FILE\n"+
		"\n"+
		"Options:\n", myName)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n"+
		"Examples:\n"+
		"  gocryptfs-xray myfs/mCXnISiv7nEmyc0glGuhTQ\n"+
		"  gocryptfs-xray -dumpmasterkey myfs/gocryptfs.conf\n"+
		"  gocryptfs-xray -encrypt-paths myfs.sock\n")
}

// sum counts the number of true values
func sum(x ...*bool) (s int) {
	for _, v := range x {
		if *v {
			s++
		}
	}
	return s
}

func main() {
	var args struct {
		dumpmasterkey *bool
		decryptPaths  *bool
		encryptPaths  *bool
		aessiv        *bool
		sep0          *bool
		fido2         *string
		version       *bool
	}
	args.dumpmasterkey = flag.Bool("dumpmasterkey", false, "Decrypt and dump the master key")
	args.decryptPaths = flag.Bool("decrypt-paths", false, "Decrypt file paths using gocryptfs control socket")
	args.encryptPaths = flag.Bool("encrypt-paths", false, "Encrypt file paths using gocryptfs control socket")
	args.sep0 = flag.Bool("0", false, "Use \\0 instead of \\n as separator")
	args.aessiv = flag.Bool("aessiv", false, "Assume AES-SIV mode instead of AES-GCM")
	args.fido2 = flag.String("fido2", "", "Protect the masterkey using a FIDO2 token instead of a password")
	args.version = flag.Bool("version", false, "Print version information")

	flag.Usage = usage
	flag.Parse()

	if *args.version {
		printVersion()
		os.Exit(0)
	}

	s := sum(args.dumpmasterkey, args.decryptPaths, args.encryptPaths)
	if s > 1 {
		fmt.Printf("fatal: %d operations were requested\n", s)
		os.Exit(1)
	}
	if flag.NArg() != 1 {
		usage()
		os.Exit(1)
	}
	fn := flag.Arg(0)
	if *args.decryptPaths {
		decryptPaths(fn, *args.sep0)
	}
	if *args.encryptPaths {
		encryptPaths(fn, *args.sep0)
	}
	fd, err := os.Open(fn)
	if err != nil {
		errExit(err)
	}
	defer fd.Close()
	if *args.dumpmasterkey {
		dumpMasterKey(fn, *args.fido2)
	} else {
		inspectCiphertext(fd, *args.aessiv)
	}
}

func dumpMasterKey(fn string, fido2Path string) {
	tlog.Info.Enabled = false
	cf, err := configfile.Load(fn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitcodes.Exit(err)
	}
	var pw []byte
	if cf.IsFeatureFlagSet(configfile.FlagFIDO2) {
		if fido2Path == "" {
			tlog.Fatal.Printf("Masterkey encrypted using FIDO2 token; need to use the --fido2 option.")
			os.Exit(exitcodes.Usage)
		}
		pw = fido2.Secret(fido2Path, cf.FIDO2.CredentialID, cf.FIDO2.HMACSalt)
	} else {
		pw = readpassword.Once(nil, nil, "")
	}
	masterkey, err := cf.DecryptMasterKey(pw)
	fmt.Println(hex.EncodeToString(masterkey))
	for i := range pw {
		pw[i] = 0
	}
}

func inspectCiphertext(fd *os.File, aessiv bool) {
	headerBytes := make([]byte, contentenc.HeaderLen)
	n, err := fd.ReadAt(headerBytes, 0)
	if err == io.EOF && n == 0 {
		fmt.Println("empty file")
		os.Exit(0)
	} else if err == io.EOF {
		fmt.Printf("incomplete file header: read %d bytes, want %d\n", n, contentenc.HeaderLen)
		os.Exit(1)
	} else if err != nil {
		errExit(err)
	}
	header, err := contentenc.ParseHeader(headerBytes)
	if err != nil {
		errExit(err)
	}
	prettyPrintHeader(header, aessiv)
	var i int64
	buf := make([]byte, blockSize)
	for i = 0; ; i++ {
		off := contentenc.HeaderLen + i*blockSize
		n, err := fd.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			errExit(err)
		}
		if n == 0 && err == io.EOF {
			break
		}
		// A block contains at least the IV, the Auth Tag and 1 data byte
		if n < ivLen+authTagLen+1 {
			errExit(fmt.Errorf("corrupt block: truncated data, len=%d", n))
		}
		data := buf[:n]
		// Parse block data
		iv := data[:ivLen]
		tag := data[len(data)-authTagLen:]
		if aessiv {
			tag = data[ivLen : ivLen+authTagLen]
		}
		fmt.Printf("Block %2d: IV: %s, Tag: %s, Offset: %5d Len: %d\n",
			i, hex.EncodeToString(iv), hex.EncodeToString(tag), off, len(data))
	}
}
