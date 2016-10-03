package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/cryptocore"
)

const (
	ivLen     = contentenc.DefaultIVBits / 8
	blockSize = contentenc.DefaultBS + ivLen + cryptocore.AuthTagLen
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
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Printf("Usage: xray FILE\n")
		os.Exit(1)
	}
	f := flag.Arg(0)
	fd, err := os.Open(f)
	if err != nil {
		errExit(err)
	}

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
