// Package holes finds and pretty-prints holes & data sections of a file.
// Used by TestFileHoleCopy in the gocryptfs test suite.
package holes

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"syscall"
	"time"
)

const (
	SEEK_DATA = 3
	SEEK_HOLE = 4

	SegmentHole = SegmentType(100)
	SegmentData = SegmentType(101)
	SegmentEOF  = SegmentType(102)
)

type Whence int

func (w Whence) String() string {
	switch w {
	case SEEK_DATA:
		return "SEEK_DATA"
	case SEEK_HOLE:
		return "SEEK_HOLE"
	default:
		return "???"
	}
}

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
	for i, s := range segments {
		out += s.String()
		if i < len(segments)-1 {
			out += "\n"
		}
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
	// starts with hole and has no data
	if err == syscall.ENXIO {
		segments = append(segments,
			Segment{0, SegmentHole},
			Segment{totalSize, SegmentEOF})
		return segments, nil
	}
	if err != nil {
		return nil, err
	}
	// starts with data
	if off == cursor {
		segments = append(segments, Segment{0, SegmentData})
	} else {
		// starts with hole
		segments = append(segments,
			Segment{0, SegmentHole},
			Segment{off, SegmentData})
		cursor = off
	}

	// now we are at the start of data.
	// find next hole, then next data, then next hole, then next data...
	for {
		oldCursor := cursor
		// Next hole
		off, err = syscall.Seek(fd, cursor, SEEK_HOLE)
		if err != nil {
			return nil, err
		}
		segments = append(segments, Segment{off, SegmentHole})
		cursor = off

		// Next data
		off, err := syscall.Seek(fd, cursor, SEEK_DATA)
		// No more data?
		if err == syscall.ENXIO {
			segments = append(segments,
				Segment{totalSize, SegmentEOF})
			break
		}
		if err != nil {
			return nil, err
		}
		segments = append(segments, Segment{off, SegmentData})
		cursor = off

		if oldCursor == cursor {
			return nil, fmt.Errorf("%s\nerror: seek loop!", PrettyPrint(segments))
		}
	}
	return segments, nil
}

// Verify `segments` using a full bytewise file scan
func Verify(fd int, segments []Segment) (err error) {
	last := segments[len(segments)-1]
	if last.Type != SegmentEOF {
		log.Panicf("BUG: last segment is not EOF. segments: %v", segments)
	}

	for i, s := range segments {
		var whence int
		switch s.Type {
		case SegmentHole:
			whence = SEEK_HOLE
		case SegmentData:
			whence = SEEK_DATA
		case SegmentEOF:
			continue
		default:
			log.Panicf("BUG: unknown segment type %d", s.Type)
		}
		for off := s.Offset; off < segments[i+1].Offset; off++ {
			res, err := syscall.Seek(fd, off, whence)
			if err != nil {
				return fmt.Errorf("error: seek(%d, %s) returned error %v", off, Whence(whence).String(), err)
			}
			if res != off {
				return fmt.Errorf("error: seek(%d, %s) returned new offset %d", off, Whence(whence).String(), res)
			}
		}
	}
	return err
}

// Create a test file at `path` with random holes
func Create(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	rand.Seed(time.Now().UnixNano())
	offsets := make([]int64, 10)
	for i := range offsets {
		offsets[i] = int64(rand.Int31n(60000))
	}

	buf := []byte("x")
	for _, off := range offsets {
		_, err = f.WriteAt(buf, off)
		if err != nil {
			panic(err)
		}
	}

	// Expand the file to 50000 bytes so we sometimes have a hole on the end
	if offsets[len(offsets)-1] < 50000 {
		f.Truncate(50000)
	}

	f.Sync()
}
