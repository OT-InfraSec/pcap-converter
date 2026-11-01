package detect

import (
	"reflect"
	"testing"
)

func seg(seq uint32, payload []byte) TCPSegment {
	return TCPSegment{Seq: seq, ACK: true, Payload: payload}
}

func TestModbusTrackerTCP(t *testing.T) {
	req := func(n uint16) []byte { return adu(n, 0, 1, 3, u16(0, 4)) }
	txns := func(ms []ModbusMessage) (out []uint16) {
		for _, m := range ms {
			out = append(out, m.TransactionID)
		}
		return
	}
	eq := func(t *testing.T, got []ModbusMessage, want ...uint16) {
		t.Helper()
		if g := txns(got); !reflect.DeepEqual(g, want) && !(len(g) == 0 && len(want) == 0) {
			t.Errorf("transactions = %v, want %v", g, want)
		}
	}
	const C, S = true, false

	t.Run("a retransmitted ADU is decoded once", func(t *testing.T) {
		tr := NewModbusTracker()
		r := req(1)
		eq(t, tr.FeedTCP("c", C, seg(1000, r), true), 1)
		eq(t, tr.FeedTCP("c", C, seg(1000, r), true))
		r2 := req(2)
		eq(t, tr.FeedTCP("c", C, seg(1000+uint32(len(r)), r2), true), 2)
		eq(t, tr.FeedTCP("c", C, seg(1000, r), true))
		eq(t, tr.FeedTCP("c", C, seg(1000+uint32(len(r)), r2), true))
	})
	t.Run("a retransmission that also carries new data", func(t *testing.T) {
		tr := NewModbusTracker()
		a, b := req(1), req(2)
		eq(t, tr.FeedTCP("c", C, seg(1000, a), true), 1)
		eq(t, tr.FeedTCP("c", C, seg(1000, cat(a, b)), true), 2)
	})
	t.Run("a retransmitted first part of a split ADU", func(t *testing.T) {
		tr := NewModbusTracker()
		first := req(1)
		tr.FeedTCP("c", C, seg(1000, first), true)
		r := req(2)
		base := 1000 + uint32(len(first))
		eq(t, tr.FeedTCP("c", C, seg(base, r[:7]), true))
		eq(t, tr.FeedTCP("c", C, seg(base, r[:7]), true))
		eq(t, tr.FeedTCP("c", C, seg(base+7, r[7:]), true), 2)
	})
	t.Run("segments out of order (G5)", func(t *testing.T) {
		tr := NewModbusTracker()
		first := req(1)
		tr.FeedTCP("c", S, seg(5000, first), true)
		resp := adu(5, 0, 1, 3, append([]byte{250}, make([]byte, 250)...))
		base := 5000 + uint32(len(first))
		eq(t, tr.FeedTCP("c", S, seg(base, resp[:100]), true))
		eq(t, tr.FeedTCP("c", S, seg(base+200, resp[200:]), true))
		eq(t, tr.FeedTCP("c", S, seg(base+100, resp[100:200]), true), 5)
	})
	t.Run("directions have their own sequence numbers", func(t *testing.T) {
		tr := NewModbusTracker()
		eq(t, tr.FeedTCP("c", C, seg(1000, req(1)), true), 1)
		eq(t, tr.FeedTCP("c", S, seg(1000, req(1)), true), 1)
		eq(t, tr.FeedTCP("c", S, seg(1000, req(1)), true))
	})
	t.Run("RST forgets the connection", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.FeedTCP("c", C, seg(1000, req(1)), true)
		tr.FeedTCP("c", C, TCPSegment{Seq: 1012, RST: true}, true)
		if tr.Known("c") {
			t.Error("connection must be forgotten")
		}
		eq(t, tr.FeedTCP("c", C, seg(1012, adu(2, 1, 1, 3, u16(0, 4))), true))
	})
	t.Run("FIN in both directions forgets the connection", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.FeedTCP("c", C, seg(1000, req(1)), true)
		tr.FeedTCP("c", C, TCPSegment{Seq: 1012, FIN: true, ACK: true}, true)
		if !tr.Known("c") {
			t.Fatal("half-closed connection is still Modbus")
		}
		tr.FeedTCP("c", S, TCPSegment{Seq: 7000, FIN: true, ACK: true}, true)
		if tr.Known("c") {
			t.Error("closed connection must be forgotten")
		}
	})
	t.Run("a new SYN on the same ports starts a new connection", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.FeedTCP("c", C, seg(1000, req(1)), true)
		tr.FeedTCP("c", C, TCPSegment{Seq: 90000, SYN: true}, true)
		if tr.Known("c") {
			t.Error("reused ports must not inherit the old connection")
		}
		// The new connection's bytes are not taken for old retransmissions.
		eq(t, tr.FeedTCP("c", C, seg(90001, req(1)), true), 1)
	})
	t.Run("SYN-ACK does not reset the connection", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.FeedTCP("c", C, seg(1000, req(1)), true)
		tr.FeedTCP("c", S, TCPSegment{Seq: 7000, SYN: true, ACK: true}, true)
		if !tr.Known("c") {
			t.Error("a SYN-ACK is the server half of the handshake")
		}
	})
	t.Run("a session that starts after the handshake", func(t *testing.T) {
		tr := NewModbusTracker()
		eq(t, tr.FeedTCP("c", C, seg(123456789, req(1)), true), 1)
		eq(t, tr.FeedTCP("c", C, seg(123456789+12, req(2)), true), 2)
	})
	t.Run("a full handshake first", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.FeedTCP("c", C, TCPSegment{Seq: 100, SYN: true}, true)
		tr.FeedTCP("c", S, TCPSegment{Seq: 900, SYN: true, ACK: true}, true)
		tr.FeedTCP("c", C, TCPSegment{Seq: 101, ACK: true}, true)
		eq(t, tr.FeedTCP("c", C, seg(101, req(1)), true), 1)
		eq(t, tr.FeedTCP("c", C, seg(101, req(1)), true))
	})
	t.Run("giving up on a gap drops the half message", func(t *testing.T) {
		tr := NewModbusTracker()
		first := req(1)
		tr.FeedTCP("c", C, seg(1000, first), true)
		r := req(2)
		base := 1000 + uint32(len(first))
		tr.FeedTCP("c", C, seg(base, r[:7]), true) // the rest never arrives
		var got []ModbusMessage
		next := base + 100
		var want []uint16
		for i := 0; i < 40; i++ {
			a := req(uint16(10 + i))
			got = append(got, tr.FeedTCP("c", C, seg(next, a), true)...)
			next += uint32(len(a))
			want = append(want, uint16(10+i))
		}
		eq(t, got, want...)
		for _, m := range got {
			if len(m.Events) != 0 {
				t.Fatalf("junk event after the gap: %+v", m)
			}
		}
	})
	t.Run("segments without payload do nothing", func(t *testing.T) {
		tr := NewModbusTracker()
		eq(t, tr.FeedTCP("c", C, TCPSegment{Seq: 5, ACK: true}, true))
		if tr.Len() != 0 {
			t.Error("no state for a connection that is not Modbus")
		}
	})
}

func FuzzModbusTrackerTCP(f *testing.F) {
	f.Add(uint32(1), adu(1, 0, 1, 3, u16(0, 4)), uint32(13), []byte{1, 2, 3}, byte(0))
	f.Fuzz(func(t *testing.T, a uint32, p []byte, b uint32, q []byte, flags byte) {
		tr := NewModbusTracker()
		tr.FeedTCP("c", true, TCPSegment{Seq: a, Payload: p}, true)
		tr.FeedTCP("c", true, TCPSegment{Seq: b, Payload: q, SYN: flags&1 != 0, FIN: flags&2 != 0, RST: flags&4 != 0, ACK: flags&8 != 0}, true)
		tr.FeedTCP("c", false, TCPSegment{Seq: a, Payload: q}, true)
		tr.FeedTCP("c", true, TCPSegment{Seq: a, Payload: p}, true)
	})
}
