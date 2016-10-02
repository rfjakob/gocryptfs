package contentenc

// Per-file header
//
// Format: [ "Version" uint16 big endian ] [ "Id" 16 random bytes ]

import (
	"encoding/binary"
	"fmt"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
)

const (
	// CurrentVersion is the current On-Disk-Format version
	CurrentVersion = 2

	headerVersionLen = 2  // uint16
	headerIDLen      = 16 // 128 bit random file id
	// HeaderLen is the total header length
	HeaderLen = headerVersionLen + headerIDLen
)

// FileHeader represents the header stored on each non-empty file.
type FileHeader struct {
	Version uint16
	ID      []byte
}

// Pack - serialize fileHeader object
func (h *FileHeader) Pack() []byte {
	if len(h.ID) != headerIDLen || h.Version != CurrentVersion {
		panic("FileHeader object not properly initialized")
	}
	buf := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(buf[0:headerVersionLen], h.Version)
	copy(buf[headerVersionLen:], h.ID)
	return buf

}

// ParseHeader - parse "buf" into fileHeader object
func ParseHeader(buf []byte) (*FileHeader, error) {
	if len(buf) != HeaderLen {
		return nil, fmt.Errorf("ParseHeader: invalid length: got %d, want %d", len(buf), HeaderLen)
	}
	var h FileHeader
	h.Version = binary.BigEndian.Uint16(buf[0:headerVersionLen])
	if h.Version != CurrentVersion {
		return nil, fmt.Errorf("ParseHeader: invalid version: got %d, want %d", h.Version, CurrentVersion)
	}
	h.ID = buf[headerVersionLen:]
	return &h, nil
}

// RandomHeader - create new fileHeader object with random Id
func RandomHeader() *FileHeader {
	var h FileHeader
	h.Version = CurrentVersion
	h.ID = cryptocore.RandBytes(headerIDLen)
	return &h
}
