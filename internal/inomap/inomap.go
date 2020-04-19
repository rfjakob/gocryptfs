// inomap translates (Dev, Flags, Ino) tuples to unique uint64
// inode numbers.
//
// Format of the returned inode numbers:
//
//   [spill bit = 0][15 bit namespace id][48 bit passthru inode number]
//   [spill bit = 1][63 bit spill inode number                        ]
//
// Each (Dev, Flags) tuple gets a namespace id assigned. The original inode
// number is then passed through in the lower 48 bits.
//
// If namespace ids are exhaused, or the original id is larger than 48 bits,
// the whole (Dev, Flags, Ino) tuple gets mapped in the spill map, and the
// spill bit is set to 1.
package inomap

import (
	"log"
	"sync"
	"syscall"
)

const (
	maxNamespaceId = 1<<15 - 1
	maxPassthruIno = 1<<48 - 1
	maxSpillIno    = 1<<63 - 1
)

// InoMap stores the maps using for inode number translation.
// See package comment for details.
type InoMap struct {
	sync.Mutex
	// namespaces keeps the mapping of (Dev,Flags) tuples to
	// uint16 identifiers
	namespaceMap map[namespaceData]uint16
	// spillNext is the next free namespace number in the namespaces map
	namespaceNext uint16
	// spill is used once the namespaces map is full
	spillMap map[QIno]uint64
	// spillNext is the next free inode number in the spill map
	spillNext uint64
}

// New returns a new InoMap.
func New() *InoMap {
	return &InoMap{
		namespaceMap:  make(map[namespaceData]uint16),
		namespaceNext: 0,
		spillMap:      make(map[QIno]uint64),
		spillNext:     0,
	}
}

func (m *InoMap) spill(in QIno) (out uint64) {
	out, found := m.spillMap[in]
	if found {
		return out
	}
	if m.spillNext >= maxSpillIno {
		log.Panicf("spillMap overflow: spillNext = 0x%x", m.spillNext)
	}
	out = m.spillNext
	m.spillNext++
	m.spillMap[in] = out
	return 1<<63 | out
}

// Translate maps the passed-in (device, inode) pair to a unique inode number.
func (m *InoMap) Translate(in QIno) (out uint64) {
	m.Lock()
	defer m.Unlock()

	if in.Ino > maxPassthruIno {
		return m.spill(in)
	}
	ns, found := m.namespaceMap[in.namespaceData]
	// Use existing namespace
	if found {
		return uint64(ns)<<48 | in.Ino
	}
	// No free namespace slots?
	if m.namespaceNext >= maxNamespaceId {
		return m.spill(in)
	}
	ns = m.namespaceNext
	m.namespaceNext++
	m.namespaceMap[in.namespaceData] = ns
	return uint64(ns)<<48 | in.Ino
}

// TranslateStat translates the inode number contained in "st" if neccessary.
// Convience wrapper around Translate().
func (m *InoMap) TranslateStat(st *syscall.Stat_t) {
	in := QInoFromStat(st)
	st.Ino = m.Translate(in)
}
