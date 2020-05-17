// Package ctlsock is a Go library that can be used to query the
// gocryptfs control socket interface. This interface can be
// activated by passing `-ctlsock /tmp/my.sock` to gocryptfs on the
// command line.
// See gocryptfs-xray for a usage example.
package ctlsock

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func (r *ResponseStruct) Error() string {
	return fmt.Sprintf("errno %d: %s", r.ErrNo, r.ErrText)
}

// CtlSock encapsulates a control socket
type CtlSock struct {
	Conn net.Conn
}

// New opens the socket at `socketPath` and stores it in a `CtlSock` object.
func New(socketPath string) (*CtlSock, error) {
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		return nil, err
	}
	return &CtlSock{Conn: conn}, nil
}

// Query sends a request to the control socket returns the response.
func (c *CtlSock) Query(req *RequestStruct) (*ResponseStruct, error) {
	c.Conn.SetDeadline(time.Now().Add(time.Second))
	msg, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	_, err = c.Conn.Write(msg)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 5000)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	var resp ResponseStruct
	json.Unmarshal(buf, &resp)
	if resp.ErrNo != 0 {
		return nil, &resp
	}
	return &resp, nil
}

// Close closes the socket
func (c *CtlSock) Close() {
	c.Conn.Close()
}
