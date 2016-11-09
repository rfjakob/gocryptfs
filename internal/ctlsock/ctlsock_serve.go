// Package ctlsock implementes the control socket interface that can be
// activated by passing "-ctlsock" on the command line.
package ctlsock

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// Interface should be implemented by fusefrontend[_reverse]
type Interface interface {
	EncryptPath(string) (string, error)
	DecryptPath(string) (string, error)
}

// RequestStruct is sent by a client
type RequestStruct struct {
	EncryptPath string
	DecryptPath string
}

// ResponseStruct is sent by us as response to a request
type ResponseStruct struct {
	// Result is the resulting decrypted or encrypted path. Empty on error.
	Result string
	// ErrNo is the error number as defined in errno.h.
	// 0 means success and -1 means that the error number is not known
	// (look at ErrText in this case).
	ErrNo int32
	// ErrText is a detailed error message.
	ErrText string
}

type ctlSockHandler struct {
	fs     Interface
	socket *net.UnixListener
}

// CreateAndServe creates an unix socket at "path" and serves incoming
// connections in a new goroutine.
func CreateAndServe(path string, fs Interface) error {
	sock, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	handler := ctlSockHandler{
		fs:     fs,
		socket: sock.(*net.UnixListener),
	}
	go handler.acceptLoop()
	return nil
}

func (ch *ctlSockHandler) acceptLoop() {
	for {
		conn, err := ch.socket.Accept()
		if err != nil {
			tlog.Warn.Printf("ctlsock: Accept error: %v", err)
			break
		}
		go ch.handleConnection(conn.(*net.UnixConn))
	}
}

func (ch *ctlSockHandler) handleConnection(conn *net.UnixConn) {
	// 2*PATH_MAX is definitely big enough for requests to decrypt or
	// encrypt paths.
	buf := make([]byte, 2*syscall.PathMax)
	for {
		n, err := conn.Read(buf)
		if err == io.EOF {
			conn.Close()
			return
		} else if err != nil {
			tlog.Warn.Printf("ctlsock: Read error: %#v", err)
			conn.Close()
			return
		}
		buf = buf[:n]
		var in RequestStruct
		err = json.Unmarshal(buf, &in)
		if err != nil {
			tlog.Warn.Printf("ctlsock: Unmarshal error: %#v", err)
			errorMsg := ResponseStruct{
				ErrNo:   int32(syscall.EINVAL),
				ErrText: err.Error(),
			}
			sendResponse(&errorMsg, conn)
		}
		ch.handleRequest(&in, conn)
		// Restore original size.
		buf = buf[:cap(buf)]
	}
}

func (ch *ctlSockHandler) handleRequest(in *RequestStruct, conn *net.UnixConn) {
	var err error
	var out ResponseStruct
	if in.DecryptPath != "" && in.EncryptPath != "" {
		err = errors.New("Ambigous")
	} else if in.DecryptPath == "" && in.EncryptPath == "" {
		err = errors.New("No operation")
	} else if in.DecryptPath != "" {
		out.Result, err = ch.fs.DecryptPath(in.DecryptPath)
	} else if in.EncryptPath != "" {
		out.Result, err = ch.fs.EncryptPath(in.EncryptPath)
	}
	if err != nil {
		out.ErrText = err.Error()
		out.ErrNo = -1
		// Try to extract the actual error number
		if pe, ok := err.(*os.PathError); ok {
			if se, ok := pe.Err.(syscall.Errno); ok {
				out.ErrNo = int32(se)
			}
		}
	}
	sendResponse(&out, conn)
}

func sendResponse(msg *ResponseStruct, conn *net.UnixConn) {
	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		tlog.Warn.Printf("ctlsock: Marshal failed: %v", err)
		return
	}
	_, err = conn.Write(jsonMsg)
	if err != nil {
		tlog.Warn.Printf("ctlsock: Write failed: %v", err)
	}
}
