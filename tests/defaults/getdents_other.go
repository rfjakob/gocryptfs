//go:build !linux

package defaults

import (
	"golang.org/x/sys/unix"
)

func getdents(fd int, buf []byte) (int, error) {
	return unix.Getdirentries(fd, buf, nil)
}
