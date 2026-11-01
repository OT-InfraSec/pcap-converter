package detect

import (
	"reflect"
	"testing"
)

func TestS7Tracker(t *testing.T) {
	setup := func(ref uint16) []byte {
		return dtFrame(s7PDU(1, ref, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil))
	}
	refs := func(ms []S7Message) (out []uint16) {
		for _, m := range ms {
			if m.HasS7 {
				out = append(out, m.PDURef)
			}
		}
		return
	}
	eq := func(t *testing.T, got []S7Message, want ...uint16) {
		t.Helper()
		if g := refs(got); !reflect.DeepEqual(g, want) && !(len(g) == 0 && len(want) == 0) {
			t.Errorf("PDU refs = %v, want %v", g, want)
		}
	}
	const C, S = true, false
	feed := func(tr *S7Tracker, dir bool, seq uint32, p []byte) []S7Message {
		return tr.FeedTCP("c", dir, TCPSegment{Seq: seq, ACK: true, Payload: p}, true)
	}
	cr := crFrame(false, []byte{0x01, 0x02}, []byte{0x01, 0x00})

	t.Run("garbage does not make a connection", func(t *testing.T) {
		tr := NewS7Tracker()
		eq(t, feed(tr, C, 1, []byte("GET / HTTP/1.1\r\nHost: plc\r\n\r\n")))
		if tr.Known("c") || tr.Len() != 0 {
			t.Error("no state expected")
		}
	})
	t.Run("MMS over COTP is not S7", func(t *testing.T) {
		tr := NewS7Tracker()
		eq(t, feed(tr, C, 1, dtFrame([]byte{0x01, 0x01, 0x01, 0x00, 0x61, 0x02, 0x02, 0x01})))
		if tr.Known("c") {
			t.Error("must not be known")
		}
	})
	t.Run("an S7 PDU recognises the connection", func(t *testing.T) {
		tr := NewS7Tracker()
		eq(t, feed(tr, C, 1, setup(1)), 1)
		if !tr.Known("c") {
			t.Error("must be known")
		}
	})
	t.Run("a connection request on the port starts the connection and gives rack and slot to later PDUs", func(t *testing.T) {
		tr := NewS7Tracker()
		ms := feed(tr, C, 1, cr)
		if len(ms) != 1 || ms[0].COTPName != "CR" || ms[0].Slot != 2 {
			t.Fatalf("%+v", ms)
		}
		if tr.SawS7("c") {
			t.Error("a connection request is not S7 yet")
		}
		ms = feed(tr, C, 1+uint32(len(cr)), setup(4))
		if len(ms) != 1 || !ms[0].HasS7 || ms[0].Rack != 0 || ms[0].Slot != 2 || !tr.SawS7("c") {
			t.Errorf("rack and slot must carry over: %+v", ms)
		}
		// The reply direction carries them too.
		ms = feed(tr, S, 100, dtFrame(s7PDU(3, 4, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil)))
		if len(ms) != 1 || ms[0].Slot != 2 {
			t.Errorf("%+v", ms)
		}
	})
	t.Run("a connection request off the port is not enough", func(t *testing.T) {
		tr := NewS7Tracker()
		if ms := tr.FeedTCP("c", C, TCPSegment{Seq: 1, Payload: cr}, false); len(ms) != 0 || tr.Known("c") {
			t.Errorf("%+v", ms)
		}
	})
	t.Run("pipelined frames", func(t *testing.T) {
		tr := NewS7Tracker()
		eq(t, feed(tr, C, 1, append(append(setup(1), setup(2)...), setup(3)...)), 1, 2, 3)
	})
	t.Run("a frame split across segments", func(t *testing.T) {
		tr := NewS7Tracker()
		feed(tr, C, 1, setup(1))
		f := setup(2)
		seq := uint32(1 + len(setup(1)))
		eq(t, feed(tr, C, seq, f[:3]))
		eq(t, feed(tr, C, seq+3, f[3:9]))
		eq(t, feed(tr, C, seq+9, f[9:]), 2)
	})
	t.Run("a bare TPKT start on the port", func(t *testing.T) {
		tr := NewS7Tracker()
		f := setup(1)
		eq(t, feed(tr, C, 1, f[:5]))
		eq(t, feed(tr, C, 6, f[5:]), 1)
	})
	t.Run("COTP fragments make one S7 PDU", func(t *testing.T) {
		tr := NewS7Tracker()
		feed(tr, C, 1, setup(1))
		pdu := s7PDU(1, 9, cat([]byte{4, 1}, s7Item(0x84, 1, 0, 0, 2, 2)), nil)
		a := tpkt([]byte{2, 0xf0, 0x00}, pdu[:9])
		b := tpkt([]byte{2, 0xf0, 0x80}, pdu[9:])
		seq := uint32(1 + len(setup(1)))
		eq(t, feed(tr, C, seq, a))
		ms := feed(tr, C, seq+uint32(len(a)), b)
		if len(ms) != 1 || ms[0].PDURef != 9 || ms[0].Function != 4 || len(ms[0].Items) != 1 {
			t.Errorf("%+v", ms)
		}
	})
	t.Run("retransmission and reordering", func(t *testing.T) {
		tr := NewS7Tracker()
		a := setup(1)
		eq(t, feed(tr, C, 100, a), 1)
		eq(t, feed(tr, C, 100, a))
		b := setup(2)
		base := uint32(100 + len(a))
		eq(t, feed(tr, C, base+5, b[5:]))
		eq(t, feed(tr, C, base, b[:5]), 2)
		eq(t, feed(tr, C, base, b[:5]))
	})
	t.Run("an invalid TPKT header drops the stream until a valid start", func(t *testing.T) {
		tr := NewS7Tracker()
		feed(tr, C, 1, setup(1))
		seq := uint32(1 + len(setup(1)))
		eq(t, feed(tr, C, seq, []byte{9, 9, 9, 9, 9, 9, 9, 9}))
		// Valid TPKT that is not S7 is not taken up while the stream is out of step.
		mms := dtFrame([]byte{0x01, 0x01, 0x01, 0x00, 0x61, 0x02, 0x02, 0x01})
		if ms := feed(tr, C, seq+8, mms); len(ms) != 0 {
			t.Errorf("a non-S7 frame must wait for a valid start: %+v", ms)
		}
		eq(t, feed(tr, C, seq+8+uint32(len(mms)), setup(5)), 5)
	})
	t.Run("after a gap garbage is dropped until a valid frame", func(t *testing.T) {
		tr := NewS7Tracker()
		feed(tr, C, 1, setup(1))
		seq := uint32(2000)
		// Whole TPKT frames of another protocol: valid framing, but after a gap they
		// are not taken up until the probe has seen a valid start.
		junk := dtFrame([]byte{0x01, 0x01, 0x01, 0x00, 0x61, 0x02, 0x02, 0x01})
		var got []S7Message
		for i := 0; i < 40; i++ {
			got = append(got, feed(tr, C, seq, junk)...)
			seq += uint32(len(junk))
		}
		if len(got) != 0 {
			t.Errorf("after a gap the data must pass the probe first: %d messages", len(got))
		}
		eq(t, feed(tr, C, seq, setup(6)), 6)
	})
	t.Run("a gap drops pending COTP fragments", func(t *testing.T) {
		tr := NewS7Tracker()
		feed(tr, C, 1, setup(1))
		stale := tpkt([]byte{2, 0xf0, 0x00}, s7PDU(1, 99, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil)) // no EOT bit
		seq := uint32(1000)
		feed(tr, C, seq, stale)
		seq += uint32(len(stale))
		junk := []byte{9, 9, 9, 9, 9, 9, 9, 9}
		seq += 5000 // bytes lost
		for i := 0; i < 40; i++ {
			feed(tr, C, seq, junk)
			seq += uint32(len(junk))
		}
		eq(t, feed(tr, C, seq, setup(6)), 6) // must not be joined with the stale fragment
	})
	t.Run("RST, FIN both ways and a new SYN end the state", func(t *testing.T) {
		tr := NewS7Tracker()
		feed(tr, C, 1, setup(1))
		tr.FeedTCP("c", C, TCPSegment{Seq: 99, RST: true}, true)
		if tr.Known("c") {
			t.Error("RST")
		}
		feed(tr, C, 1, setup(1))
		tr.FeedTCP("c", C, TCPSegment{Seq: 99, FIN: true, ACK: true}, true)
		tr.FeedTCP("c", S, TCPSegment{Seq: 500, FIN: true, ACK: true}, true)
		if tr.Known("c") {
			t.Error("FIN")
		}
		feed(tr, C, 1, setup(1))
		tr.FeedTCP("c", C, TCPSegment{Seq: 9000, SYN: true}, true)
		if tr.Known("c") {
			t.Error("SYN")
		}
	})
	t.Run("bounded", func(t *testing.T) {
		tr := NewS7TrackerLimit(2)
		for _, k := range []string{"a", "b", "c", "d"} {
			tr.FeedTCP(k, C, TCPSegment{Seq: 1, Payload: setup(1)}, true)
		}
		if tr.Len() > 2 {
			t.Errorf("tracked %d", tr.Len())
		}
		eq(t, tr.FeedTCP("z", C, TCPSegment{Seq: 1, Payload: setup(7)}, true), 7)
	})
}

func FuzzS7Tracker(f *testing.F) {
	f.Add(dtFrame(s7PDU(1, 1, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil)), []byte{3, 0, 0, 20, 2}, uint32(5))
	f.Fuzz(func(t *testing.T, a, b []byte, seq uint32) {
		tr := NewS7Tracker()
		tr.FeedTCP("c", true, TCPSegment{Seq: seq, Payload: a}, true)
		tr.FeedTCP("c", true, TCPSegment{Seq: seq + uint32(len(a)), Payload: b}, true)
		tr.FeedTCP("c", false, TCPSegment{Seq: seq, Payload: b, SYN: true}, true)
	})
}
