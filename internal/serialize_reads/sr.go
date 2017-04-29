package serialize_reads

import (
	"log"
	"sync"
	"time"

	"github.com/rfjakob/gocryptfs/internal/tlog"
)

// serializerState is used by the Wait and Done functions
type serializerState struct {
	// we get submissions through the "input" channel
	input chan *submission
	// q = Queue
	q []*submission
	// wg is used to wait for the read to complete before unblocking the next
	wg sync.WaitGroup
}

// Wait places the caller into a queue and blocks
func Wait(offset int64, size int) {
	serializer.wait(offset, size)
}

// Done signals that the read operation has finished
func Done() {
	serializer.wg.Done()
}

type submission struct {
	// "ch" is closed by "eventLoop" once it wants to unblock the caller
	ch chan struct{}
	// submissions are prioritized by offset (lowest offset gets unblocked first)
	offset int64
	// size will be used in the future to detect consecutive read requests. These
	// can be unblocked immediately.
	size int
}

func (sr *serializerState) wait(offset int64, size int) {
	ch := make(chan struct{})
	sb := &submission{
		ch:     ch,
		offset: offset,
		size:   size,
	}
	// Send our submission
	sr.input <- sb
	// Wait till we get unblocked
	<-ch
}

// push returns true if the queue is full after the element has been stored.
// It panics if it did not have space to store the element.
func (sr *serializerState) push(sb *submission) (full bool) {
	free := 0
	stored := false
	for i, v := range sr.q {
		if v != nil {
			continue
		}
		if !stored {
			sr.q[i] = sb
			stored = true
			continue
		}
		free++
	}
	if !stored {
		// This should never happen because eventLoop checks if the queue got full
		log.Panic("BUG: unhandled queue overflow")
	}
	if free == 0 {
		return true
	}
	return false
}

// pop the submission with the lowest offset off the queue
func (sr *serializerState) pop() *submission {
	var winner *submission
	var winnerIndex int
	for i, v := range sr.q {
		if v == nil {
			continue
		}
		if winner == nil {
			winner = v
			winnerIndex = i
			continue
		}
		if v.offset < winner.offset {
			winner = v
			winnerIndex = i
		}
	}
	if winner == nil {
		return nil
	}
	sr.q[winnerIndex] = nil
	return winner
}

func (sr *serializerState) eventLoop() {
	sr.input = make(chan *submission)
	empty := true
	for {
		if empty {
			// If the queue is empty we block on the channel to conserve CPU
			sb := <-sr.input
			sr.push(sb)
			empty = false
		}
		select {
		case sb := <-sr.input:
			full := sr.push(sb)
			if full {
				// Queue is full, unblock the new request immediately
				tlog.Warn.Printf("serialize_reads: queue full, forcing unblock")
				sr.unblockOne()
			}
			continue
		case <-time.After(time.Microsecond * 500):
			// Looks like we have waited out all concurrent requests.
			empty = sr.unblockOne()
		}
	}
}

// Unblock a submission and wait for completion
func (sr *serializerState) unblockOne() (empty bool) {
	winner := sr.pop()
	if winner == nil {
		return true
	}
	sr.wg.Add(1)
	close(winner.ch)
	sr.wg.Wait()
	return false
}

var serializer serializerState

// InitSerializer sets up the internal serializer state and starts the event loop.
// Called by fusefrontend.NewFS.
func InitSerializer() {
	serializer.input = make(chan *submission)
	serializer.q = make([]*submission, 10)
	go serializer.eventLoop()
}
