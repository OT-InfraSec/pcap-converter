package tcpseq

import (
	"bytes"
	"testing"
)

func push(t *testing.T, s *Stream, seq uint32, payload string) (string, bool) {
	t.Helper()
	d, gap := s.Push(seq, false, []byte(payload))
	return string(d), gap
}

func want(t *testing.T, got string, gap bool, wantData string, wantGap bool) {
	t.Helper()
	if got != wantData || gap != wantGap {
		t.Errorf("got %q gap=%v, want %q gap=%v", got, gap, wantData, wantGap)
	}
}

func TestStreamInOrder(t *testing.T) {
	var s Stream
	d, g := push(t, &s, 1000, "abc")
	want(t, d, g, "abc", false)
	d, g = push(t, &s, 1003, "def")
	want(t, d, g, "def", false)
}

func TestStreamRetransmission(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "abc")
	d, g := push(t, &s, 1000, "abc")
	want(t, d, g, "", false)
	push(t, &s, 1003, "def")
	d, g = push(t, &s, 1000, "abc")
	want(t, d, g, "", false)
	d, g = push(t, &s, 1003, "def")
	want(t, d, g, "", false)
}

func TestStreamPartialOverlap(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "abc")
	// A retransmission that also carries new bytes: only the new ones count.
	d, g := push(t, &s, 1001, "bcdef")
	want(t, d, g, "def", false)
	d, g = push(t, &s, 1004, "efg")
	want(t, d, g, "g", false)
}

func TestStreamOutOfOrder(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "abc")
	d, g := push(t, &s, 1006, "ghi")
	want(t, d, g, "", false)
	d, g = push(t, &s, 1009, "jkl")
	want(t, d, g, "", false)
	d, g = push(t, &s, 1003, "def")
	want(t, d, g, "defghijkl", false)
	d, g = push(t, &s, 1012, "m")
	want(t, d, g, "m", false)
}

func TestStreamOutOfOrderDuplicateAndOverlap(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "abc")
	push(t, &s, 1006, "ghi")
	d, g := push(t, &s, 1006, "ghi") // duplicate of a buffered segment
	want(t, d, g, "", false)
	d, g = push(t, &s, 1003, "defgh") // covers the gap and part of the buffered one
	want(t, d, g, "defghi", false)
}

func TestStreamWraparound(t *testing.T) {
	var s Stream
	d, g := push(t, &s, 0xfffffffe, "abcd") // ends at 2
	want(t, d, g, "abcd", false)
	d, g = push(t, &s, 2, "ef")
	want(t, d, g, "ef", false)
	d, g = push(t, &s, 0xfffffffe, "abcd")
	want(t, d, g, "", false)
	// Out of order across the wrap.
	var s2 Stream
	push(t, &s2, 0xfffffffd, "ab") // next 0xffffffff
	d, g = push(t, &s2, 1, "yz")
	want(t, d, g, "", false)
	d, g = push(t, &s2, 0xffffffff, "mn")
	want(t, d, g, "mnyz", false)
}

func TestStreamSYN(t *testing.T) {
	var s Stream
	d, _ := s.Push(5000, true, nil)
	if len(d) != 0 {
		t.Fatal("SYN carries no data")
	}
	// The first data byte is ISN+1.
	got, g := push(t, &s, 5001, "abc")
	want(t, got, g, "abc", false)
	// A retransmitted SYN does not disturb the stream.
	s.Push(5000, true, nil)
	got, g = push(t, &s, 5004, "d")
	want(t, got, g, "d", false)
}

func TestStreamMidstreamStartAcceptsFirstSegment(t *testing.T) {
	var s Stream
	d, g := push(t, &s, 123456, "abc")
	want(t, d, g, "abc", false)
}

func TestStreamFirstCopyWinsOnConflict(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "abc")
	d, g := push(t, &s, 1000, "xyz")
	want(t, d, g, "", false)
}

func TestStreamGivesUpOnALargeGap(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "abc") // next 1003, 1003 never arrives
	var d string
	var g bool
	for i := 0; i < MaxPendingSegments+1; i++ {
		d, g = push(t, &s, uint32(2000+i*10), "0123456789")
		if g {
			break
		}
	}
	if !g {
		t.Fatal("expected a gap after too many buffered segments")
	}
	if len(d) == 0 || d[:10] != "0123456789" {
		t.Errorf("after giving up the buffered data is delivered, got %q", d)
	}
	// The stream carries on after the gap.
	nxt := uint32(2000 + 10*len(d)/10)
	d2, g2 := push(t, &s, nxt, "z")
	want(t, d2, g2, "z", false)
}

func TestStreamResyncsOnAHugeJump(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "abc")
	d, g := push(t, &s, 1000+MaxWindow+10, "new")
	want(t, d, g, "new", true)
	d, g = push(t, &s, 1000+MaxWindow+13, "x")
	want(t, d, g, "x", false)
	// And far behind.
	d, g = push(t, &s, 1000, "old")
	want(t, d, g, "old", true)
}

func TestStreamBuffersAreBounded(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "a")
	big := bytes.Repeat([]byte("x"), MaxPendingBytes/2+1)
	s.Push(1100, false, big)
	_, gap := s.Push(1100+uint32(len(big))+10, false, big)
	if !gap {
		t.Error("exceeding the byte limit must give up on the gap")
	}
}

func FuzzStream(f *testing.F) {
	f.Add(uint32(1), []byte("abc"), uint32(10), []byte("def"))
	f.Fuzz(func(t *testing.T, a uint32, p []byte, b uint32, q []byte) {
		var s Stream
		s.Push(a, false, p)
		s.Push(b, false, q)
		s.Push(a, true, nil)
		s.Push(b, false, q)
	})
}

func TestStreamSYNFixesThePositionForEarlySegments(t *testing.T) {
	var s Stream
	s.Push(5000, true, nil)
	// A later segment arrives before the first data segment: it must wait.
	d, g := push(t, &s, 5004, "d")
	want(t, d, g, "", false)
	d, g = push(t, &s, 5001, "abc")
	want(t, d, g, "abcd", false)
}

func TestStreamPendingOrderAcrossWraparound(t *testing.T) {
	var s Stream
	push(t, &s, 0xfffffffb, "ab") // next 0xfffffffd
	push(t, &s, 1, "yz")
	push(t, &s, 0xffffffff, "mn")
	d, g := push(t, &s, 0xfffffffd, "cd")
	want(t, d, g, "cdmnyz", false)
}

func TestStreamHeldDuplicatesDoNotUseUpTheBuffer(t *testing.T) {
	var s Stream
	push(t, &s, 1000, "a")
	for i := 0; i < 3*MaxPendingSegments; i++ {
		if _, gap := push(t, &s, 1100, "late"); gap {
			t.Fatal("a repeated segment must not count again")
		}
	}
	d, g := push(t, &s, 1001, string(make([]byte, 99)))
	if g || len(d) != 99+4 {
		t.Errorf("got %d bytes gap=%v", len(d), g)
	}
}
