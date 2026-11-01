// Package tcpseq tracks the sequence numbers of one direction of a TCP
// connection, so that a consumer sees each payload byte once and in order:
// retransmissions and overlaps are dropped, and segments that arrive early are
// held until the gap before them is filled.
//
// It is deliberately small. It does not model windows, timers, SACK or
// out-of-window data. When a gap does not close within the buffer limits the
// stream gives up on the missing bytes, reports the gap, and continues from the
// data it holds; the consumer must then discard any half-parsed message.
package tcpseq

import "sort"

const (
	// MaxPendingSegments and MaxPendingBytes bound what is held for a gap.
	MaxPendingSegments = 32
	MaxPendingBytes    = 64 * 1024
	// MaxWindow is the largest distance from the expected sequence number
	// still treated as the same stream. Beyond it (a capture that skips a lot,
	// a reused port without SYN) the stream resynchronises on the segment.
	MaxWindow = 1 << 20
)

type segment struct {
	seq  uint32
	data []byte
}

// Stream is one direction of a connection. The zero value is ready: the first
// segment fixes the position (a capture may start inside a connection).
type Stream struct {
	next         uint32
	started      bool
	pending      []segment
	pendingBytes int
}

// Push adds a segment and returns the payload bytes that are new and in order,
// possibly together with earlier buffered segments it completes. gap is true
// when the stream had to skip missing bytes. syn marks a segment with the SYN
// flag, which uses one sequence number before the data.
//
// The returned slice may alias payload; the caller must not modify it.
func (s *Stream) Push(seq uint32, syn bool, payload []byte) (data []byte, gap bool) {
	if syn {
		if !s.started {
			s.next, s.started = seq+1, true
		}
		seq++
	}
	if len(payload) == 0 {
		return nil, false
	}
	if !s.started {
		s.next, s.started = seq+uint32(len(payload)), true
		return payload, false
	}

	d := int32(seq - s.next)
	if d > MaxWindow || d < -MaxWindow {
		s.pending, s.pendingBytes = nil, 0
		s.next = seq + uint32(len(payload))
		return payload, true
	}
	if d <= 0 {
		skip := int(-d)
		if skip >= len(payload) {
			return nil, false // all of it was seen before
		}
		payload = payload[skip:]
		s.next += uint32(len(payload))
		if more := s.drain(); len(more) > 0 {
			payload = append(append(make([]byte, 0, len(payload)+len(more)), payload...), more...)
		}
		return payload, false
	}

	// Ahead of the expected position: hold it.
	for _, p := range s.pending {
		if p.seq == seq && len(p.data) >= len(payload) {
			return nil, false // already held
		}
	}
	s.pending = append(s.pending, segment{seq: seq, data: append([]byte(nil), payload...)})
	s.pendingBytes += len(payload)
	if len(s.pending) > MaxPendingSegments || s.pendingBytes > MaxPendingBytes {
		return s.giveUp(), true
	}
	return nil, false
}

// drain delivers buffered segments that now start at or before next.
func (s *Stream) drain() []byte {
	if len(s.pending) == 0 {
		return nil
	}
	sort.Slice(s.pending, func(i, j int) bool {
		return int32(s.pending[i].seq-s.next) < int32(s.pending[j].seq-s.next)
	})
	var out []byte
	kept := s.pending[:0]
	for i, p := range s.pending {
		d := int32(p.seq - s.next)
		if d > 0 {
			kept = append(kept, s.pending[i:]...)
			break
		}
		skip := int(-d)
		s.pendingBytes -= len(p.data)
		if skip >= len(p.data) {
			continue
		}
		out = append(out, p.data[skip:]...)
		s.next += uint32(len(p.data) - skip)
	}
	s.pending = kept
	return out
}

// giveUp abandons the missing bytes: it moves to the earliest held segment and
// delivers what is held from there.
func (s *Stream) giveUp() []byte {
	sort.Slice(s.pending, func(i, j int) bool {
		return int32(s.pending[i].seq-s.next) < int32(s.pending[j].seq-s.next)
	})
	s.next = s.pending[0].seq
	return s.drain()
}
