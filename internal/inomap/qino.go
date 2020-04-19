package inomap

import (
	"syscall"
)

type namespaceData struct {
	// Stat_t.Dev is uint64 on 32- and 64-bit Linux
	Dev uint64
	// Flags acts like an extension of the Dev field.
	// It is used by reverse mode for virtual files.
	Flags uint8
}

// QIno = Qualified Inode number.
// Uniquely identifies a backing file through the device number,
// inode number pair.
type QIno struct {
	namespaceData
	// Stat_t.Ino is uint64 on 32- and 64-bit Linu
	Ino uint64
}

// QInoFromStat fills a new QIno struct with the passed Stat_t info.
func QInoFromStat(st *syscall.Stat_t) QIno {
	return QIno{
		namespaceData: namespaceData{
			// There are some architectures that use 32-bit values here
			// (darwin, freebsd-32, maybe others). Add an explicit cast to make
			// this function work everywhere.
			Dev: uint64(st.Dev),
		},
		Ino: uint64(st.Ino),
	}
}
