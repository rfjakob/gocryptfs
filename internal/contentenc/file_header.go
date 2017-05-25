package contentenc

// Per-file header
//
// Format: [ "Version" uint16 big endian ] [ "Id" 16 random bytes ]

import (
	"bytes"
	"encoding/binary"
	"log"
	"syscall"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/tlog"
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
		log.Panic("FileHeader object not properly initialized")
	}
	buf := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(buf[0:headerVersionLen], h.Version)
	copy(buf[headerVersionLen:], h.ID)
	return buf

}

// allZeroFileID is preallocated to quickly check if the data read from disk is all zero
var allZeroFileID = make([]byte, headerIDLen)

// ParseHeader - parse "buf" into fileHeader object
func ParseHeader(buf []byte) (*FileHeader, error) {
	if len(buf) != HeaderLen {
		tlog.Warn.Printf("ParseHeader: invalid length: want %d bytes, got %d. Returning EINVAL.", HeaderLen, len(buf))
		return nil, syscall.EINVAL
	}
	var h FileHeader
	h.Version = binary.BigEndian.Uint16(buf[0:headerVersionLen])
	if h.Version != CurrentVersion {
		tlog.Warn.Printf("ParseHeader: invalid version: want %d, got %d. Returning EINVAL.", CurrentVersion, h.Version)
		return nil, syscall.EINVAL
	}
	h.ID = buf[headerVersionLen:]
	if bytes.Equal(h.ID, allZeroFileID) {
		tlog.Warn.Printf("ParseHeader: file id is all-zero. Returning EINVAL.")
		return nil, syscall.EINVAL
	}
	return &h, nil
}

// RandomHeader - create new fileHeader object with random Id
func RandomHeader() *FileHeader {
	var h FileHeader
	h.Version = CurrentVersion
	h.ID = cryptocore.RandBytes(headerIDLen)
	return &h
}
