package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/rfjakob/gocryptfs/ctlsock"
)

func decryptPaths(socketPath string) {
	var req ctlsock.RequestStruct
	transformPaths(socketPath, &req, &req.DecryptPath)
}

func encryptPaths(socketPath string) {
	var req ctlsock.RequestStruct
	transformPaths(socketPath, &req, &req.EncryptPath)
}

func transformPaths(socketPath string, req *ctlsock.RequestStruct, in *string) {
	c, err := ctlsock.New(socketPath)
	if err != nil {
		fmt.Printf("fatal: %v\n", err)
		os.Exit(1)
	}
	line := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line++
		*in = scanner.Text()
		resp, err := c.Query(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error at input line %d %q: %v\n", line, *in, err)
			continue
		}
		if resp.WarnText != "" {
			fmt.Fprintf(os.Stderr, "warning at input line %d %q: %v\n", line, *in, resp.WarnText)
		}
		fmt.Println(resp.Result)
	}
	os.Exit(0)
}
