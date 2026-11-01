package detect

import (
	"reflect"
	"testing"
)

func TestENIPTracker(t *testing.T) {
	reg := func(session uint32) []byte { return enipPDU(ENIPRegisterSession, session, 0, []byte{1, 0, 0, 0}) }
	sessions := func(ms []ENIPMessage) (out []uint32) {
		for _, m := range ms {
			out = append(out, m.Session)
		}
		return
	}
	eq := func(t *testing.T, got []ENIPMessage, want ...uint32) {
		t.Helper()
		if g := sessions(got); !reflect.DeepEqual(g, want) && !(len(g) == 0 && len(want) == 0) {
			t.Errorf("sessions = %v, want %v", g, want)
		}
	}
	const C, S = true, false
	feed := func(tr *ENIPTracker, dir bool, seq uint32, p []byte) []ENIPMessage {
		return tr.FeedTCP("c", dir, TCPSegment{Seq: seq, ACK: true, Payload: p}, true)
	}

	t.Run("garbage does not make a connection", func(t *testing.T) {
		tr := NewENIPTracker()
		eq(t, feed(tr, C, 1, []byte("GET / HTTP/1.1\r\nHost: plc\r\n\r\n")))
		if tr.Known("c") || tr.Len() != 0 {
			t.Error("no state expected")
		}
	})
	t.Run("a valid message recognises the connection", func(t *testing.T) {
		tr := NewENIPTracker()
		eq(t, feed(tr, C, 1, reg(1)), 1)
		if !tr.Known("c") {
			t.Error("must be known")
		}
	})
	t.Run("after recognition any command is decoded", func(t *testing.T) {
		tr := NewENIPTracker()
		odd := enipPDU(0x7777, 9, 0, []byte{1, 2})
		eq(t, feed(tr, C, 1, odd))
		feed(tr, C, 1, reg(1))
		eq(t, feed(tr, C, 1+28, odd), 9)
	})
	t.Run("pipelined messages", func(t *testing.T) {
		tr := NewENIPTracker()
		eq(t, feed(tr, C, 1, append(append(reg(1), reg(2)...), reg(3)...)), 1, 2, 3)
	})
	t.Run("header and payload in separate segments", func(t *testing.T) {
		tr := NewENIPTracker()
		feed(tr, C, 1, reg(1))
		r := reg(2)
		eq(t, feed(tr, C, 29, r[:24]))
		eq(t, feed(tr, C, 53, r[24:]), 2)
	})
	t.Run("a bare header first on the ENIP port", func(t *testing.T) {
		tr := NewENIPTracker()
		r := reg(1)
		eq(t, feed(tr, C, 1, r[:10]))
		eq(t, feed(tr, C, 11, r[10:]), 1)
	})
	t.Run("a long message in many segments", func(t *testing.T) {
		tr := NewENIPTracker()
		feed(tr, C, 1, reg(1))
		pdu := enipPDU(ENIPSendRRData, 1, 0, rrData(append([]byte{0x4d, 1, 0x91, 0}, make([]byte, 600)...)))
		seq := uint32(29)
		var got []ENIPMessage
		for i := 0; i < len(pdu); i += 100 {
			end := i + 100
			if end > len(pdu) {
				end = len(pdu)
			}
			got = append(got, feed(tr, C, seq, pdu[i:end])...)
			seq += uint32(end - i)
		}
		eq(t, got, 1)
	})
	t.Run("retransmission and reordering", func(t *testing.T) {
		tr := NewENIPTracker()
		a, b := reg(1), reg(2)
		eq(t, feed(tr, C, 100, a), 1)
		eq(t, feed(tr, C, 100, a))
		pdu := enipPDU(ENIPSendRRData, 1, 0, rrData([]byte{0x0e, 2, 0x20, 1, 0x24, 1}))
		base := uint32(100 + len(a))
		eq(t, feed(tr, C, base+10, pdu[10:]))
		eq(t, feed(tr, C, base, pdu[:10]), 1)
		eq(t, feed(tr, C, base, pdu[:10]))
		_ = b
	})
	t.Run("after a gap garbage is dropped until a valid header", func(t *testing.T) {
		tr := NewENIPTracker()
		feed(tr, C, 1, reg(1))
		// 40 segments ahead of a hole: the stream gives up on the hole.
		var got []ENIPMessage
		seq := uint32(1000)
		junk := []byte("this is the middle of some message, not a header...........")
		for i := 0; i < 40; i++ {
			got = append(got, feed(tr, C, seq, junk)...)
			seq += uint32(len(junk))
		}
		eq(t, got)
		eq(t, feed(tr, C, seq, reg(5)), 5)
	})
	t.Run("RST, FIN both ways and a new SYN end the state", func(t *testing.T) {
		tr := NewENIPTracker()
		feed(tr, C, 1, reg(1))
		tr.FeedTCP("c", C, TCPSegment{Seq: 29, RST: true}, true)
		if tr.Known("c") {
			t.Error("RST")
		}
		feed(tr, C, 1, reg(1))
		tr.FeedTCP("c", C, TCPSegment{Seq: 29, FIN: true, ACK: true}, true)
		tr.FeedTCP("c", S, TCPSegment{Seq: 500, FIN: true, ACK: true}, true)
		if tr.Known("c") {
			t.Error("FIN")
		}
		feed(tr, C, 1, reg(1))
		tr.FeedTCP("c", C, TCPSegment{Seq: 9000, SYN: true}, true)
		if tr.Known("c") {
			t.Error("SYN")
		}
	})
	t.Run("directions and connections are separate", func(t *testing.T) {
		tr := NewENIPTracker()
		eq(t, feed(tr, C, 1, reg(1)), 1)
		eq(t, feed(tr, S, 1, reg(1)), 1)
		eq(t, tr.FeedTCP("other", C, TCPSegment{Seq: 1, Payload: enipPDU(0x7777, 3, 0, nil)}, true))
	})
	t.Run("bounded", func(t *testing.T) {
		tr := NewENIPTrackerLimit(2)
		for _, k := range []string{"a", "b", "c", "d"} {
			tr.FeedTCP(k, C, TCPSegment{Seq: 1, Payload: reg(1)}, true)
		}
		if tr.Len() > 2 {
			t.Errorf("tracked %d", tr.Len())
		}
		eq(t, tr.FeedTCP("z", C, TCPSegment{Seq: 1, Payload: reg(7)}, true), 7)
	})
}

func TestDecodeENIPDatagram(t *testing.T) {
	m, ok := DecodeENIPDatagram(enipPDU(ENIPListIdentity, 0, 0, nil))
	if !ok || m.Command != ENIPListIdentity {
		t.Fatalf("%+v ok=%v", m, ok)
	}
	// A datagram is one message: trailing bytes are ignored, a short one fails.
	if _, ok := DecodeENIPDatagram(append(enipPDU(ENIPNop, 0, 0, nil), 1, 2)); !ok {
		t.Error("trailing bytes must not matter")
	}
	if _, ok := DecodeENIPDatagram(enipPDU(ENIPListIdentity, 0, 0, nil)[:20]); ok {
		t.Error("short datagram")
	}
	// Not ENIP: the strict probe applies, there is no connection to rely on.
	if _, ok := DecodeENIPDatagram(enipPDU(0x7777, 0, 0, nil)); ok {
		t.Error("unknown command in a datagram")
	}
}

func FuzzENIPTracker(f *testing.F) {
	f.Add(enipPDU(ENIPRegisterSession, 1, 0, []byte{1, 0, 0, 0}), []byte{1, 2, 3}, uint32(5))
	f.Fuzz(func(t *testing.T, a, b []byte, seq uint32) {
		tr := NewENIPTracker()
		tr.FeedTCP("c", true, TCPSegment{Seq: seq, Payload: a}, true)
		tr.FeedTCP("c", true, TCPSegment{Seq: seq + uint32(len(a)), Payload: b}, true)
		tr.FeedTCP("c", false, TCPSegment{Seq: seq, Payload: b, SYN: true}, true)
		DecodeENIPDatagram(a)
	})
}
