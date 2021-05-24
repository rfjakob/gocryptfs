// Package holes finds and pretty-prints holes & data sections of a file.
// Used by TestFileHoleCopy in the gocryptfs test suite.
package holes

import (
	"fmt"
	"syscall"
)

const (
	SEEK_DATA = 3
	SEEK_HOLE = 4

	SegmentHole = SegmentType(100)
	SegmentData = SegmentType(101)
	SegmentEOF  = SegmentType(102)
)

type Segment struct {
	Offset int64
	Type   SegmentType
}

func (s Segment) String() string {
	return fmt.Sprintf("%10d %v", s.Offset, s.Type)
}

type SegmentType int

func (s SegmentType) String() string {
	switch s {
	case SegmentHole:
		return "hole"
	case SegmentData:
		return "data"
	case SegmentEOF:
		return "eof"
	default:
		return "???"
	}
}

// PrettyPrint pretty-prints the Segments.
func PrettyPrint(segments []Segment) (out string) {
	for _, s := range segments {
		out += "\n" + s.String()
	}
	return out
}

// Find examines the file passed via file descriptor and returns the found holes
// and data sections.
func Find(fd int) (segments []Segment, err error) {
	var st syscall.Stat_t
	err = syscall.Fstat(fd, &st)
	if err != nil {
		return nil, err
	}
	totalSize := st.Size

	var cursor int64

	// find out if file starts with data or hole
	off, err := syscall.Seek(fd, 0, SEEK_DATA)
	if err == syscall.ENXIO {
		segments = append(segments,
			Segment{0, SegmentHole},
			Segment{totalSize, SegmentEOF})
		return segments, nil
	}
	if err != nil {
		return nil, err
	}
	if off == cursor {
		segments = append(segments, Segment{0, SegmentData})
	} else {
		segments = append(segments,
			Segment{0, SegmentHole},
			Segment{totalSize, SegmentData})
		cursor = off
	}

	// now we are at the start of data.
	// find next hole, then next data, then next hole, then next data...
	for {
		cursor, err = syscall.Seek(fd, cursor, SEEK_HOLE)
		if err != nil {
			return nil, err
		}
		if cursor == totalSize {
			segments = append(segments, Segment{cursor, SegmentEOF})
			break
		}
		segments = append(segments, Segment{cursor, SegmentHole})
		cursor, err = syscall.Seek(fd, cursor, SEEK_DATA)
		if err != nil {
			return nil, err
		}
		if cursor == totalSize {
			segments = append(segments, Segment{cursor, SegmentEOF})
			break
		}
		segments = append(segments, Segment{cursor, SegmentData})
	}
	return segments, nil
}
