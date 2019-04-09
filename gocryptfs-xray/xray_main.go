package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rfjakob/gocryptfs/internal/configfile"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/readpassword"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

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

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] FILE\n"+
		"\n"+
		"Options:\n", myName)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n"+
		"Examples:\n"+
		"  gocryptfs-xray myfs/mCXnISiv7nEmyc0glGuhTQ\n"+
		"  gocryptfs-xray -dumpmasterkey myfs/gocryptfs.conf\n")
}

func main() {
	dumpmasterkey := flag.Bool("dumpmasterkey", false, "Decrypt and dump the master key")
	aessiv := flag.Bool("aessiv", false, "Assume AES-SIV mode instead of AES-GCM")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() != 1 {
		usage()
		os.Exit(1)
	}
	fn := flag.Arg(0)
	fd, err := os.Open(fn)
	if err != nil {
		errExit(err)
	}
	defer fd.Close()
	if *dumpmasterkey {
		dumpMasterKey(fn)
	} else {
		inspectCiphertext(fd, *aessiv)
	}
}

func dumpMasterKey(fn string) {
	tlog.Info.Enabled = false
	pw := readpassword.Once(nil, "", "")
	masterkey, _, err := configfile.LoadAndDecrypt(fn, pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitcodes.Exit(err)
	}
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
