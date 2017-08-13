// +build !linux

package syscallcompat

import (
	"log"

	"github.com/hanwen/go-fuse/fuse"
)

// HaveGetdents is true if we have a working implementation of Getdents
const HaveGetdents = false

func Getdents(dir string) ([]fuse.DirEntry, error) {
	log.Panic("only implemented on Linux")
	return nil, nil
}
