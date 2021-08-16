package inomap

import (
	"syscall"
)

type namespaceData struct {
	// Stat_t.Dev is uint64 on 32- and 64-bit Linux
	Dev uint64
	// Tag acts like an extension of the Dev field.
	// It is used by reverse mode for virtual files.
	// Normal (forward) mode does not use it and it
	// stays always zero there.
	Tag uint8
}

// QIno = Qualified Inode number.
// Uniquely identifies a backing file through the
// (device number, tag, inode number) tuple.
type QIno struct {
	namespaceData
	// Stat_t.Ino is uint64 on 32- and 64-bit Linu
	Ino uint64
}

// NewQIno returns a filled QIno struct
func NewQIno(dev uint64, tag uint8, ino uint64) QIno {
	return QIno{
		namespaceData: namespaceData{
			Dev: dev,
			Tag: tag,
		},
		Ino: ino,
	}
}

// QInoFromStat fills a new QIno struct with the passed Stat_t info.
func QInoFromStat(st *syscall.Stat_t) QIno {
	// There are some architectures that use 32-bit values here
	// (darwin, freebsd-32, maybe others). Add an explicit cast to make
	// this function work everywhere.
	return NewQIno(uint64(st.Dev), 0, uint64(st.Ino))
}
