package fido2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

type fidoCommand int

const (
	cred          fidoCommand = iota
	assert        fidoCommand = iota
	assertWithPIN fidoCommand = iota
)

const relyingPartyID = "gocryptfs"

func callFidoCommand(command fidoCommand, device string, stdin []string) ([]string, error) {
	var cmd *exec.Cmd
	switch command {
	case cred:
		cmd = exec.Command("fido2-cred", "-M", "-h", "-v", device)
	case assert:
		cmd = exec.Command("fido2-assert", "-G", "-h", device)
	case assertWithPIN:
		cmd = exec.Command("fido2-assert", "-G", "-h", "-v", device)
	}
	tlog.Debug.Printf("callFidoCommand: executing %q with args %v", cmd.Path, cmd.Args)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	for _, s := range stdin {
		// This does not deadlock because the pipe buffer is big enough (64kiB on Linux)
		io.WriteString(in, s+"\n")
	}
	in.Close()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s failed with %v", cmd.Args[0], err)
	}
	return strings.Split(string(out), "\n"), nil
}

// Register registers a credential using a FIDO2 token
func Register(device string, userName string) (credentialID []byte) {
	tlog.Info.Printf("FIDO2 Register: interact with your device ...")
	cdh := base64.StdEncoding.EncodeToString(cryptocore.RandBytes(32))
	userID := base64.StdEncoding.EncodeToString(cryptocore.RandBytes(32))
	stdin := []string{cdh, relyingPartyID, userName, userID}
	out, err := callFidoCommand(cred, device, stdin)
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.FIDO2Error)
	}
	credentialID, err = base64.StdEncoding.DecodeString(out[4])
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.FIDO2Error)
	}
	return credentialID
}

// Secret generates a HMAC secret using a FIDO2 token
func Secret(device string, credentialID []byte, salt []byte) (secret []byte) {
	tlog.Info.Printf("FIDO2 Secret: interact with your device ...")
	cdh := base64.StdEncoding.EncodeToString(cryptocore.RandBytes(32))
	crid := base64.StdEncoding.EncodeToString(credentialID)
	hmacsalt := base64.StdEncoding.EncodeToString(salt)
	stdin := []string{cdh, relyingPartyID, crid, hmacsalt}
	// try asserting without PIN first
	out, err := callFidoCommand(assert, device, stdin)
	if err != nil {
		// if that fails, let's assert with PIN
		out, err = callFidoCommand(assertWithPIN, device, stdin)
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.FIDO2Error)
		}
	}
	secret, err = base64.StdEncoding.DecodeString(out[4])
	if err != nil {
		tlog.Fatal.Println(err)
		os.Exit(exitcodes.FIDO2Error)
	}

	// sanity checks
	secretLen := len(secret)
	if secretLen < 32 {
		tlog.Fatal.Printf("FIDO2 HMACSecret too short (%d)!\n", secretLen)
		os.Exit(exitcodes.FIDO2Error)
	}
	zero := make([]byte, secretLen)
	if bytes.Equal(zero, secret) {
		tlog.Fatal.Printf("FIDO2 HMACSecret is all zero!")
		os.Exit(exitcodes.FIDO2Error)
	}

	return secret
}
