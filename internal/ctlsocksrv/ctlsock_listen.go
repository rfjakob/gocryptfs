package ctlsocksrv

import (
	"net"
)

func Listen(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
