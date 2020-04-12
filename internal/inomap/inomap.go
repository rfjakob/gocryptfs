package inomap

import (
	"sync"
	"syscall"
)

// UINT64_MAX           = 18446744073709551615
const inumTranslateBase = 10000000000000000000

// InoMap ... see New() for description.
type InoMap struct {
	sync.Mutex
	baseDev       uint64
	translate     map[QIno]uint64
	translateNext uint64
}

// New returns a new InoMap.
//
// InoMap translates (device uint64, inode uint64) pairs to unique uint64
// inode numbers.
// Inode numbers on the "baseDev" are passed through unchanged (as long as they
// are not higher than inumTranslateBase).
// Inode numbers on other devices are remapped to the number space above
// 10000000000000000000. The mapping is stored in a simple Go map. Entries
// can only be added and are never removed.
func New(baseDev uint64) *InoMap {
	return &InoMap{
		baseDev:       baseDev,
		translate:     make(map[QIno]uint64),
		translateNext: inumTranslateBase,
	}
}

// Translate maps the passed-in (device, inode) pair to a unique inode number.
func (m *InoMap) Translate(in QIno) (out uint64) {
	if in.Dev == m.baseDev && in.Ino < inumTranslateBase {
		return in.Ino
	}
	m.Lock()
	defer m.Unlock()
	out = m.translate[in]
	if out != 0 {
		return out
	}
	out = m.translateNext
	m.translate[in] = m.translateNext
	m.translateNext++
	return out
}

// TranslateStat translates the inode number contained in "st" if neccessary.
// Convience wrapper around Translate().
func (m *InoMap) TranslateStat(st *syscall.Stat_t) {
	in := QInoFromStat(st)
	st.Ino = m.Translate(in)
}

// Count returns the number of entries in the translation table.
func (m *InoMap) Count() int {
	return len(m.translate)
}
