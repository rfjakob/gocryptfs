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
	ivLen     = contentenc.DefaultIVBits / 8
	blockSize = contentenc.DefaultBS + ivLen + cryptocore.AuthTagLen
	myName    = "gocryptfs-xray"
)

func errExit(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func prettyPrintHeader(h *contentenc.FileHeader) {
	id := hex.EncodeToString(h.ID)
	fmt.Printf("Header: Version: %d, Id: %s\n", h.Version, id)
}

func main() {
	dumpmasterkey := flag.Bool("dumpmasterkey", false, "Decrypt and dump the master key")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] FILE\n"+
			"\n"+
			"Options:\n", myName)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n"+
			"Examples:\n"+
			"  gocryptfs-xray myfs/mCXnISiv7nEmyc0glGuhTQ\n"+
			"  gocryptfs-xray -dumpmasterkey myfs/gocryptfs.conf\n")
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
		inspectCiphertext(fd)
	}
}

func dumpMasterKey(fn string) {
	tlog.Info.Enabled = false
	pw := readpassword.Once("", "")
	masterkey, _, err := configfile.Load(fn, pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitcodes.Exit(err)
	}
	fmt.Println(hex.EncodeToString(masterkey))
	for i := range pw {
		pw[i] = 0
	}
}

func inspectCiphertext(fd *os.File) {
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
	prettyPrintHeader(header)
	var i int64
	for i = 0; ; i++ {
		blockLen := int64(blockSize)
		off := contentenc.HeaderLen + i*blockSize
		iv := make([]byte, ivLen)
		_, err := fd.ReadAt(iv, off)
		if err == io.EOF {
			break
		} else if err != nil {
			errExit(err)
		}
		tag := make([]byte, cryptocore.AuthTagLen)
		_, err = fd.ReadAt(tag, off+blockSize-cryptocore.AuthTagLen)
		if err == io.EOF {
			fi, err2 := fd.Stat()
			if err2 != nil {
				errExit(err2)
			}
			_, err2 = fd.ReadAt(tag, fi.Size()-cryptocore.AuthTagLen)
			if err2 != nil {
				errExit(err2)
			}
			blockLen = (fi.Size() - contentenc.HeaderLen) % blockSize
		} else if err != nil {
			errExit(err)
		}
		fmt.Printf("Block %2d: IV: %s, Tag: %s, Offset: %5d Len: %d\n",
			i, hex.EncodeToString(iv), hex.EncodeToString(tag), off, blockLen)
	}
}
