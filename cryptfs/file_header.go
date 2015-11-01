package cryptfs

// Per-file header
//
// Format: [ "Version" uint16 big endian ] [ "Id" 16 random bytes ]

import (
	"encoding/binary"
	"fmt"
)

const (
	HEADER_CURRENT_VERSION  = 1 // Current on-disk-format version
	HEADER_VERSION_LEN = 2 // uint16
	HEADER_ID_LEN = 16 // 128 bit random file id
	HEADER_LEN = HEADER_VERSION_LEN + HEADER_ID_LEN // Total header length
)

type FileHeader struct {
	Version uint16
	Id []byte
}

// Pack - serialize fileHeader object
func (h *FileHeader) Pack() []byte {
	if len(h.Id) != HEADER_ID_LEN || h.Version != HEADER_CURRENT_VERSION {
		panic("FileHeader object not properly initialized")
	}
	buf := make([]byte, HEADER_LEN)
	binary.BigEndian.PutUint16(buf[0:HEADER_VERSION_LEN], h.Version)
	copy(buf[HEADER_VERSION_LEN:], h.Id)
	return buf

}

// ParseHeader - parse "buf" into fileHeader object
func ParseHeader(buf []byte) (*FileHeader, error) {
	if len(buf) != HEADER_LEN {
		return nil, fmt.Errorf("ParseHeader: invalid length: got %d, want %d", len(buf), HEADER_LEN)
	}
	var h FileHeader
	h.Version = binary.BigEndian.Uint16(buf[0:HEADER_VERSION_LEN])
	if h.Version != HEADER_CURRENT_VERSION {
		return nil, fmt.Errorf("ParseHeader: invalid version: got %d, want %d", h.Version, HEADER_CURRENT_VERSION)
	}
	h.Id = buf[HEADER_VERSION_LEN:]
	return &h, nil
}

// RandomHeader - create new fileHeader object with random Id
func RandomHeader() *FileHeader {
	var h FileHeader
	h.Version = HEADER_CURRENT_VERSION
	h.Id = RandBytes(HEADER_ID_LEN)
	return &h
}
