// inomap translates (Dev, Tag, Ino) tuples to unique uint64
// inode numbers.
//
// Format of the returned inode numbers:
//
//	[spill bit = 0][15 bit namespace id][48 bit passthru inode number]
//	[spill bit = 1][63 bit spill inode number                        ]
//
// Each (Dev, Tag) tuple gets a namespace id assigned. The original inode
// number is then passed through in the lower 48 bits.
//
// If namespace ids are exhausted, or the original id is larger than 48 bits,
// the whole (Dev, Tag, Ino) tuple gets mapped in the spill map, and the
// spill bit is set to 1.
package inomap

import (
	"log"
	"sync"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// max value of 15 bit namespace id
	maxNamespaceId = 1<<15 - 1
	// max value of 48 bit passthru inode number
	maxPassthruIno = 1<<48 - 1
	// max value of 63 bit spill inode number
	maxSpillIno = 1<<63 - 1
	// bit 63 is used as the spill bit
	spillBit = 1 << 63
)

// InoMap stores the maps using for inode number translation.
// See package comment for details.
type InoMap struct {
	sync.Mutex
	// namespaceMap keeps the mapping of (Dev,Flags) tuples to
	// 15-bit identifiers (stored in an uint16 with the high bit always zero)
	namespaceMap map[namespaceData]uint16
	// spillNext is the next free namespace number in the namespaces map
	namespaceNext uint16
	// spill is used once the namespaces map is full
	spillMap map[QIno]uint64
	// spillNext is the next free inode number in the spill map
	spillNext uint64
}

// New returns a new InoMap.
// Inode numbers on device `rootDev` will be passed through as-is.
// If `rootDev` is zero, the first Translate() call decides the effective
// rootDev.
func New(rootDev uint64) *InoMap {
	m := &InoMap{
		namespaceMap:  make(map[namespaceData]uint16),
		namespaceNext: 0,
		spillMap:      make(map[QIno]uint64),
		spillNext:     0,
	}
	if rootDev > 0 {
		// Reserve namespace 0 for rootDev
		m.namespaceMap[namespaceData{rootDev, 0}] = 0
		m.namespaceNext = 1
	}
	return m
}

var spillWarn sync.Once

func (m *InoMap) spill(in QIno) (out uint64) {
	spillWarn.Do(func() { tlog.Warn.Printf("InoMap: opening spillMap for %v", in) })

	out, found := m.spillMap[in]
	if found {
		return out | spillBit
	}
	if m.spillNext >= maxSpillIno {
		log.Panicf("spillMap overflow: spillNext = 0x%x", m.spillNext)
	}
	out = m.spillNext
	m.spillNext++
	m.spillMap[in] = out
	return out | spillBit
}

// Translate maps the passed-in (device, inode) pair to a unique inode number.
func (m *InoMap) Translate(in QIno) (out uint64) {
	m.Lock()
	defer m.Unlock()

	if in.Ino > maxPassthruIno {
		out = m.spill(in)
		return out
	}
	ns, found := m.namespaceMap[in.namespaceData]
	// Use existing namespace
	if found {
		out = uint64(ns)<<48 | in.Ino
		return out
	}
	// No free namespace slots?
	if m.namespaceNext >= maxNamespaceId {
		out = m.spill(in)
		return out
	}
	ns = m.namespaceNext
	m.namespaceNext++
	m.namespaceMap[in.namespaceData] = ns
	out = uint64(ns)<<48 | in.Ino
	return out
}

// TranslateStat translates (device, ino) pair contained in "st" into a unique
// inode number and overwrites the ino in "st" with it.
// Convenience wrapper around Translate().
func (m *InoMap) TranslateStat(st *syscall.Stat_t) {
	in := QInoFromStat(st)
	st.Ino = m.Translate(in)
}
