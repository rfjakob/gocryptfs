package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
)

func decryptPaths(socketPath string, sep0 bool) {
	var req ctlsock.RequestStruct
	transformPaths(socketPath, &req, &req.DecryptPath, sep0)
}

func encryptPaths(socketPath string, sep0 bool) {
	var req ctlsock.RequestStruct
	transformPaths(socketPath, &req, &req.EncryptPath, sep0)
}

func transformPaths(socketPath string, req *ctlsock.RequestStruct, in *string, sep0 bool) {
	errorCount := 0
	c, err := ctlsock.New(socketPath)
	if err != nil {
		fmt.Printf("fatal: %v\n", err)
		os.Exit(1)
	}
	line := 1
	var separator byte = '\n'
	if sep0 {
		separator = '\000'
	}
	r := bufio.NewReader(os.Stdin)
	for eof := false; !eof; line++ {
		val, err := r.ReadBytes(separator)
		if len(val) == 0 {
			break
		}
		if err != nil {
			// break the loop after we have processed the last val
			eof = true
		} else {
			// drop trailing separator
			val = val[:len(val)-1]
		}
		*in = string(val)
		resp, err := c.Query(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error at input line %d %q: %v\n", line, *in, err)
			errorCount++
			continue
		}
		if resp.WarnText != "" {
			fmt.Fprintf(os.Stderr, "warning at input line %d %q: %v\n", line, *in, resp.WarnText)
		}
		fmt.Printf("%s%c", resp.Result, separator)
	}
	if errorCount == 0 {
		os.Exit(0)
	}
	os.Exit(1)
}
