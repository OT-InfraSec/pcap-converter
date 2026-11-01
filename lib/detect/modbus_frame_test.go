package detect

import (
	"reflect"
	"testing"
)

func TestDecodeModbusFrameFraming(t *testing.T) {
	P, F, L := ModbusEventInvalidProtocolID, ModbusEventInvalidFunction, ModbusEventInvalidLength
	long := append([]byte{0, 9, 0, 0, 0, 255}, make([]byte, 255)...) // length 255, 261 bytes
	tests := []struct {
		name    string
		in      []byte
		request bool
		ok      bool
		txn     uint16
		unit    byte
		fc, raw byte
		events  []string
	}{
		{"length 0 consumes the 6-byte header", []byte{0, 7, 0, 0, 0, 0}, true, true, 7, 0, 0, 0, []string{L}},
		{"length 1", []byte{0, 7, 0, 0, 0, 1, 1}, true, true, 7, 0, 0, 0, []string{L}},
		{"length 255", long, true, true, 9, 0, 0, 0, []string{L}},
		{"protocol id and length 0", []byte{0, 7, 0, 5, 0, 0}, true, true, 7, 0, 0, 0, []string{P, L}},
		{"in-range length but incomplete", []byte{0, 7, 0, 0, 0, 6, 1, 3}, true, false, 0, 0, 0, 0, nil},
		{"less than a header", []byte{0, 7, 0, 0, 0}, true, false, 0, 0, 0, 0, nil},
		{"request with fc 0", adu(1, 0, 1, 0, []byte{0, 1}), true, true, 1, 1, 0, 0, []string{F}},
		{"request with fc 0x80", adu(1, 0, 1, 0x80, []byte{0, 1}), true, true, 1, 1, 0, 0x80, []string{F}},
		{"request with fc 0xff", adu(1, 0, 1, 0xff, []byte{0, 1}), true, true, 1, 1, 0x7f, 0xff, []string{F, ModbusEventUnknownFunction}},
		{"response with fc 0 has no event", adu(1, 0, 1, 0, []byte{0, 1}), false, true, 1, 1, 0, 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := DecodeModbusADU(tc.in, tc.request)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if m.TransactionID != tc.txn || m.UnitID != tc.unit || m.FunctionCode != tc.fc || m.RawFunction != tc.raw {
				t.Errorf("got %+v", m)
			}
			if !reflect.DeepEqual(m.Events, tc.events) {
				t.Errorf("events = %v, want %v", m.Events, tc.events)
			}
		})
	}
}

// A request carrying the exception bit is not an exception: it is an invalid
// function code, and the body is still read as the underlying function, as
// sawp-modbus (Suricata) does.
func TestDecodeModbusADURequestWithExceptionBit(t *testing.T) {
	m, ok := DecodeModbusADU(adu(1, 0, 1, 0x83, u16(0x10, 4)), true)
	if !ok || m.IsException {
		t.Fatalf("%+v ok=%v", m, ok)
	}
	if m.FunctionCode != 3 || m.RawFunction != 0x83 || m.Address != 0x10 || m.Quantity != 4 {
		t.Errorf("got %+v", m)
	}
	if !reflect.DeepEqual(m.Events, []string{ModbusEventInvalidFunction}) {
		t.Errorf("events = %v", m.Events)
	}
	// The same bytes as a response are an exception.
	r, _ := DecodeModbusADU(adu(1, 0, 1, 0x83, []byte{2}), false)
	if !r.IsException || r.RawFunction != 0x83 {
		t.Errorf("response: %+v", r)
	}
}

func TestModbusTracker(t *testing.T) {
	req := func(n uint16) []byte { return adu(n, 0, 1, 3, u16(0, 4)) }
	resp := func(n uint16) []byte { return adu(n, 0, 1, 3, append([]byte{8}, make([]byte, 8)...)) }
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

	t.Run("garbage is not Modbus and leaves no state", func(t *testing.T) {
		tr := NewModbusTracker()
		eq(t, tr.Feed("c", true, []byte("GET / HTTP/1.1\r\nHost: x\r\n"), true))
		if tr.Known("c") {
			t.Error("connection must not be known")
		}
	})
	t.Run("a valid ADU recognises the connection", func(t *testing.T) {
		tr := NewModbusTracker()
		eq(t, tr.Feed("c", true, req(1), true), 1)
		if !tr.Known("c") {
			t.Error("connection must be known")
		}
	})
	t.Run("malformed ADUs are decoded only on a recognised connection", func(t *testing.T) {
		bad := adu(2, 1, 1, 3, u16(0, 4))
		tr := NewModbusTracker()
		eq(t, tr.Feed("c", true, bad, true))
		tr.Feed("c", true, req(1), true)
		ms := tr.Feed("c", true, bad, true)
		eq(t, ms, 2)
		if !reflect.DeepEqual(ms[0].Events, []string{ModbusEventInvalidProtocolID}) {
			t.Errorf("events = %v", ms[0].Events)
		}
	})
	t.Run("pipelined ADUs", func(t *testing.T) {
		tr := NewModbusTracker()
		eq(t, tr.Feed("c", true, cat(req(1), req(2), req(3)), true), 1, 2, 3)
	})
	t.Run("header in one segment, PDU in the next (E9)", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.Feed("c", true, req(1), true)
		r := req(2)
		eq(t, tr.Feed("c", true, r[:7], true))
		eq(t, tr.Feed("c", true, r[7:], true), 2)
	})
	t.Run("first segment is a bare header (H5)", func(t *testing.T) {
		tr := NewModbusTracker()
		r := req(1)
		eq(t, tr.Feed("c", true, r[:7], true))
		eq(t, tr.Feed("c", true, r[7:], true), 1)
		if !tr.Known("c") {
			t.Error("connection must be known")
		}
	})
	t.Run("bare header off the Modbus port is not buffered", func(t *testing.T) {
		tr := NewModbusTracker()
		r := req(1)
		eq(t, tr.Feed("c", true, r[:7], false))
		eq(t, tr.Feed("c", true, r[7:], false))
	})
	t.Run("pipelined with the last ADU split (G2)", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.Feed("c", true, req(9), true)
		all := cat(req(1), req(2), req(3))
		cut := len(all) - 5
		eq(t, tr.Feed("c", true, all[:cut], true), 1, 2)
		eq(t, tr.Feed("c", true, all[cut:], true), 3)
	})
	t.Run("long response in three segments (G3, G9)", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.Feed("c", true, req(9), true)
		r := adu(5, 0, 1, 3, append([]byte{250}, make([]byte, 250)...))
		eq(t, tr.Feed("c", false, r[:100], true))
		eq(t, tr.Feed("c", false, r[100:200], true))
		eq(t, tr.Feed("c", false, r[200:], true), 5)
	})
	t.Run("one byte per segment", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.Feed("c", true, req(9), true)
		r := resp(4)
		var got []ModbusMessage
		for i := range r {
			got = append(got, tr.Feed("c", false, r[i:i+1], true)...)
		}
		eq(t, got, 4)
	})
	t.Run("directions do not share a buffer", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.Feed("c", true, req(9), true)
		r := req(2)
		tr.Feed("c", true, r[:7], true)
		eq(t, tr.Feed("c", false, resp(2), true), 2)
		eq(t, tr.Feed("c", true, r[7:], true), 2)
	})
	t.Run("connections do not share state", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.Feed("a", true, req(1), true)
		eq(t, tr.Feed("b", true, adu(2, 1, 1, 3, u16(0, 4)), true))
	})
	t.Run("out-of-range length consumes the whole segment, the next is parsed afresh", func(t *testing.T) {
		tr := NewModbusTracker()
		tr.Feed("c", true, req(1), true)
		bad := append([]byte{0, 7, 0, 0, 0, 255}, make([]byte, 100)...)
		ms := tr.Feed("c", true, bad, true)
		eq(t, ms, 7)
		if !reflect.DeepEqual(ms[0].Events, []string{ModbusEventInvalidLength}) {
			t.Errorf("events = %v", ms[0].Events)
		}
		eq(t, tr.Feed("c", true, req(8), true), 8)
	})
	t.Run("the tracker is bounded", func(t *testing.T) {
		tr := NewModbusTrackerLimit(2)
		for _, k := range []string{"a", "b", "c", "d"} {
			tr.Feed(k, true, req(1), true)
		}
		if tr.Len() > 2 {
			t.Errorf("tracked %d connections", tr.Len())
		}
		// Untracked connections are still decoded, only without state.
		eq(t, tr.Feed("z", true, req(5), true), 5)
	})
}

func FuzzModbusTracker(f *testing.F) {
	f.Add(adu(1, 0, 1, 3, u16(0, 4)), []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		tr := NewModbusTracker()
		tr.Feed("c", true, a, true)
		tr.Feed("c", true, b, true)
		tr.Feed("c", false, a, true)
	})
}
