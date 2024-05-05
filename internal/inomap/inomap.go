// inomap translates (Dev, Tag, Ino) tuples to unique uint64
// inode numbers.
//
// Format of the returned inode numbers:
//
//	[spill bit = 0][15 bit namespace id][48 bit passthru inode number] = 64 bit translated inode number
//	[spill bit = 1][63 bit counter                                   ] = 64 bit spill inode number
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
	"math"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// max value of 15 bit namespace id
	maxNamespaceId = 1<<15 - 1
	// max value of 48 bit passthru inode number
	maxPassthruIno = 1<<48 - 1
	// the spill inode number space starts at 0b10000...0.
	spillSpaceStart = 1 << 63
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
		spillNext:     spillSpaceStart,
	}
	if rootDev > 0 {
		// Reserve namespace 0 for rootDev
		m.namespaceMap[namespaceData{rootDev, 0}] = 0
		m.namespaceNext = 1
	}
	return m
}

var spillWarn sync.Once

// NextSpillIno returns a fresh inode number from the spill pool without adding it to
// spillMap.
// Reverse mode NextSpillIno() for gocryptfs.longname.*.name files where a stable
// mapping is not needed.
func (m *InoMap) NextSpillIno() (out uint64) {
	if m.spillNext == math.MaxUint64 {
		log.Panicf("spillMap overflow: spillNext = 0x%x", m.spillNext)
	}
	return atomic.AddUint64(&m.spillNext, 1) - 1
}

func (m *InoMap) spill(in QIno) (out uint64) {
	spillWarn.Do(func() { tlog.Warn.Printf("InoMap: opening spillMap for %#v", in) })

	out, found := m.spillMap[in]
	if found {
		return out
	}

	out = m.NextSpillIno()
	m.spillMap[in] = out

	return out
}

// Translate maps the passed-in (device, tag, inode) tuple to a unique inode number.
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
