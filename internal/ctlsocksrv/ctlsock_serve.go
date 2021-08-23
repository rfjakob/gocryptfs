// Package ctlsocksrv implements the control socket interface that can be
// activated by passing "-ctlsock" on the command line.
package ctlsocksrv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// Interface should be implemented by fusefrontend[_reverse]
type Interface interface {
	EncryptPath(string) (string, error)
	DecryptPath(string) (string, error)
}

type ctlSockHandler struct {
	fs     Interface
	socket *net.UnixListener
}

// Serve serves incoming connections on "sock". This call blocks so you
// probably want to run it in a new goroutine.
func Serve(sock net.Listener, fs Interface) {
	handler := ctlSockHandler{
		fs:     fs,
		socket: sock.(*net.UnixListener),
	}
	handler.acceptLoop()
}

func (ch *ctlSockHandler) acceptLoop() {
	for {
		conn, err := ch.socket.Accept()
		if err != nil {
			// This can trigger on program exit with "use of closed network connection".
			// Special-casing this is hard due to https://github.com/golang/go/issues/4373
			// so just don't use tlog.Warn to not cause panics in the tests.
			tlog.Info.Printf("ctlsock: Accept error: %v", err)
			break
		}
		go ch.handleConnection(conn.(*net.UnixConn))
	}
}

// ReadBufSize is the size of the request read buffer.
// The longest possible path is 4096 bytes on Linux and 1024 on Mac OS X so
// 5000 bytes should be enough to hold the whole JSON request. This
// assumes that the path does not contain too many characters that had to be
// be escaped in JSON (for example, a null byte blows up to "\u0000").
// We abort the connection if the request is bigger than this.
const ReadBufSize = 5000

// handleConnection reads and parses JSON requests from "conn"
func (ch *ctlSockHandler) handleConnection(conn *net.UnixConn) {
	buf := make([]byte, ReadBufSize)
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
		if n == ReadBufSize {
			tlog.Warn.Printf("ctlsock: request too big (max = %d bytes)", ReadBufSize-1)
			conn.Close()
			return
		}
		data := buf[:n]
		var in ctlsock.RequestStruct
		err = json.Unmarshal(data, &in)
		if err != nil {
			tlog.Warn.Printf("ctlsock: JSON Unmarshal error: %#v", err)
			err = errors.New("JSON Unmarshal error: " + err.Error())
			sendResponse(conn, err, "", "")
			continue
		}
		ch.handleRequest(&in, conn)
	}
}

// handleRequest handles an already-unmarshaled JSON request
func (ch *ctlSockHandler) handleRequest(in *ctlsock.RequestStruct, conn *net.UnixConn) {
	var err error
	var inPath, outPath, clean, warnText string
	// You cannot perform both decryption and encryption in one request
	if in.DecryptPath != "" && in.EncryptPath != "" {
		err = errors.New("Ambiguous")
		sendResponse(conn, err, "", "")
		return
	}
	// Neither encryption nor encryption has been requested, makes no sense
	if in.DecryptPath == "" && in.EncryptPath == "" {
		err = errors.New("Empty input")
		sendResponse(conn, err, "", "")
		return
	}
	// Canonicalize input path
	if in.EncryptPath != "" {
		inPath = in.EncryptPath
	} else {
		inPath = in.DecryptPath
	}
	clean = SanitizePath(inPath)
	// Warn if a non-canonical path was passed
	if inPath != clean {
		warnText = fmt.Sprintf("Non-canonical input path '%s' has been interpreted as '%s'.", inPath, clean)
	}
	// Error out if the canonical path is now empty
	if clean == "" {
		err = errors.New("Empty input after canonicalization")
		sendResponse(conn, err, "", warnText)
		return
	}
	// Actual encrypt or decrypt operation
	if in.EncryptPath != "" {
		outPath, err = ch.fs.EncryptPath(clean)
	} else {
		outPath, err = ch.fs.DecryptPath(clean)
	}
	sendResponse(conn, err, outPath, warnText)
}

// sendResponse sends a JSON response message
func sendResponse(conn *net.UnixConn, err error, result string, warnText string) {
	msg := ctlsock.ResponseStruct{
		Result:   result,
		WarnText: warnText,
	}
	if err != nil {
		msg.ErrText = err.Error()
		msg.ErrNo = -1
		// Try to extract the actual error number
		if pe, ok := err.(*os.PathError); ok {
			if se, ok := pe.Err.(syscall.Errno); ok {
				msg.ErrNo = int32(se)
			}
		} else if err == syscall.ENOENT {
			msg.ErrNo = int32(syscall.ENOENT)
		}
	}
	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		tlog.Warn.Printf("ctlsock: Marshal failed: %v", err)
		return
	}
	// For convenience for the user, add a newline at the end.
	jsonMsg = append(jsonMsg, '\n')
	_, err = conn.Write(jsonMsg)
	if err != nil {
		tlog.Warn.Printf("ctlsock: Write failed: %v", err)
	}
}
