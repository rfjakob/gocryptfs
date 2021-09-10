package inomap

import (
	"sync"
	"testing"
)

func TestTranslate(t *testing.T) {
	m := New(0)
	q := QIno{Ino: 1}
	out := m.Translate(q)
	if out != 1 {
		t.Errorf("expected 1, got %d", out)
	}
	q.Ino = maxPassthruIno
	out = m.Translate(q)
	if out < maxPassthruIno {
		t.Errorf("got %d", out)
	}
	out2 := m.Translate(q)
	if out2 != out {
		t.Errorf("unstable mapping: %d %d", out2, out)
	}
}

func TestTranslateStress(t *testing.T) {
	const baseDev = 12345
	m := New(baseDev)

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		// Some normal inode numbers on baseDev
		var q QIno
		q.Dev = baseDev
		for i := uint64(1); i <= 10000; i++ {
			q.Ino = i
			out := m.Translate(q)
			if out != i {
				t.Errorf("i=%d out=%d", i, out)
				break
			}
		}
		wg.Done()
	}()
	go func() {
		// Very high (>maxPassthruIno) inode numbers on baseDev
		var q QIno
		q.Dev = baseDev
		for i := uint64(1); i <= 10000; i++ {
			q.Ino = maxPassthruIno + i
			out := m.Translate(q)
			if out < maxPassthruIno {
				t.Errorf("out=%d", out)
				break
			}
		}
		wg.Done()
	}()
	go func() {
		// Device 9999999
		var q QIno
		q.Dev = 9999999
		for i := uint64(1); i <= 10000; i++ {
			q.Ino = i
			out := m.Translate(q)
			if out < maxPassthruIno {
				t.Errorf("out=%d", out)
				break
			}
		}
		wg.Done()
	}()
	go func() {
		// Device 4444444
		var q QIno
		q.Dev = 4444444
		for i := uint64(1); i <= 10000; i++ {
			q.Ino = i
			out := m.Translate(q)
			if out < maxPassthruIno {
				t.Errorf("out=%d", out)
				break
			}
		}
		wg.Done()
	}()
	wg.Wait()
	if len(m.spillMap) != 10000 {
		t.Errorf("len=%d", len(m.spillMap))
	}
	if len(m.namespaceMap) != 3 {
		t.Errorf("len=%d", len(m.namespaceMap))
	}
}

func TestSpill(t *testing.T) {
	m := New(0)
	var q QIno
	q.Ino = maxPassthruIno + 1
	out1 := m.Translate(q)
	if out1&spillBit == 0 {
		t.Error("spill bit not set")
	}
	out2 := m.Translate(q)
	if out2&spillBit == 0 {
		t.Error("spill bit not set")
	}
	if out1 != out2 {
		t.Errorf("unstable mapping: %d vs %d", out1, out2)
	}
}

// TestUniqueness checks that unique (Dev, Flags, Ino) tuples get unique inode
// numbers
func TestUniqueness(t *testing.T) {
	m := New(0)
	var q QIno
	outMap := make(map[uint64]struct{})
	for q.Dev = 0; q.Dev < 10; q.Dev++ {
		for q.Tag = 0; q.Tag < 10; q.Tag++ {
			// some go into spill
			for q.Ino = maxPassthruIno - 100; q.Ino < maxPassthruIno+100; q.Ino++ {
				out := m.Translate(q)
				_, found := outMap[out]
				if found {
					t.Fatalf("inode number %d already used", out)
				}
				outMap[out] = struct{}{}
			}
		}
	}
	if len(outMap) != 10*10*200 {
		t.Errorf("%d", len(outMap))
	}
}

func BenchmarkTranslateSingleDev(b *testing.B) {
	m := New(0)
	var q QIno
	for n := 0; n < b.N; n++ {
		q.Ino = uint64(n % 1000)
		m.Translate(q)
	}
}

func BenchmarkTranslateManyDevs(b *testing.B) {
	m := New(0)
	var q QIno
	for n := 0; n < b.N; n++ {
		q.Dev = uint64(n % 10)
		q.Ino = uint64(n % 1000)
		m.Translate(q)
	}
}
