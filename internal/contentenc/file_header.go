package contentenc

// Per-file header
//
// Format: [ "Version" uint16 big endian ] [ "Id" 16 random bytes ]

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
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
var allZeroHeader = make([]byte, HeaderLen)

// ParseHeader - parse "buf" into fileHeader object
func ParseHeader(buf []byte) (*FileHeader, error) {
	if len(buf) != HeaderLen {
		return nil, fmt.Errorf("ParseHeader: invalid length, want=%d have=%d", HeaderLen, len(buf))
	}
	if bytes.Equal(buf, allZeroHeader) {
		return nil, fmt.Errorf("ParseHeader: header is all-zero. Header hexdump: %s", hex.EncodeToString(buf))
	}
	var h FileHeader
	h.Version = binary.BigEndian.Uint16(buf[0:headerVersionLen])
	if h.Version != CurrentVersion {
		return nil, fmt.Errorf("ParseHeader: invalid version, want=%d have=%d. Header hexdump: %s",
			CurrentVersion, h.Version, hex.EncodeToString(buf))
	}
	h.ID = buf[headerVersionLen:]
	if bytes.Equal(h.ID, allZeroFileID) {
		return nil, fmt.Errorf("ParseHeader: file id is all-zero. Header hexdump: %s",
			hex.EncodeToString(buf))
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
