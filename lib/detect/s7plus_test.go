package detect

import "testing"

// s7PlusPDU builds an S7CommPlus PDU: header, data of a request or response,
// trailer.
func s7PlusPDU(version, opcode byte, function, seq uint16, session uint32) []byte {
	data := []byte{opcode, 0, 0, byte(function >> 8), byte(function), 0, 0, byte(seq >> 8), byte(seq),
		byte(session >> 24), byte(session >> 16), byte(session >> 8), byte(session), 0x34, 0}
	pdu := []byte{S7PlusProtocolID, version, byte(len(data) >> 8), byte(len(data))}
	pdu = append(pdu, data...)
	return append(pdu, S7PlusProtocolID, version, 0, 0)
}

func TestProbeS7Plus(t *testing.T) {
	good := dtFrame(s7PlusPDU(1, s7PlusOpRequest, 0x04bb, 1, 0))
	cases := []struct {
		name string
		in   []byte
		want Result
	}{
		{"empty", nil, Incomplete},
		{"S7comm is not S7CommPlus", dtFrame(s7PDU(1, 1, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil)), Unrecognized},
		{"data TPDU", good, Recognized},
		{"version 3", dtFrame(s7PlusPDU(3, s7PlusOpResponse, 0x04bb, 1, 0)), Recognized},
		{"version 0", dtFrame(s7PlusPDU(0, s7PlusOpRequest, 0x04bb, 1, 0)), Unrecognized},
		{"version 9", dtFrame(s7PlusPDU(9, s7PlusOpRequest, 0x04bb, 1, 0)), Unrecognized},
		{"connection request", crFrame(false, []byte{1, 2}, []byte{1, 0}), Incomplete},
		{"cut after protocol id", good[:8], Incomplete},
		{"HTTP", []byte("GET / HTTP/1.1\r\n\r\n"), Unrecognized},
	}
	for _, c := range cases {
		if got := ProbeS7Plus(c.in); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if ProbeS7(good) != Unrecognized {
		t.Error("ProbeS7 must keep rejecting 0x72")
	}
	for i := 0; i < len(good); i++ { // truncation never panics
		ProbeS7Plus(good[:i])
	}
}

func TestDecodeS7Plus(t *testing.T) {
	frame := func(p []byte) []S7Frame {
		f, _, ok := ParseS7Frame(dtFrame(p))
		if !ok {
			t.Fatal("frame")
		}
		return []S7Frame{f}
	}
	m := MessageFromFrames(frame(s7PlusPDU(1, s7PlusOpRequest, 0x04bb, 7, 0x12345678)))
	h := m.Plus
	if h == nil || m.HasS7 {
		t.Fatalf("%+v", m)
	}
	if h.Version != 1 || h.OpcodeName != "Request" || h.Function != 0x04bb || h.FunctionName != "Explore" ||
		h.Sequence != 7 || h.SessionID != 0x12345678 || !h.TrailerOK || !h.HasFields {
		t.Errorf("%+v", h)
	}
	if len(m.Events) != 0 {
		t.Errorf("events %v", m.Events)
	}
	if u := MessageFromFrames(frame(s7PlusPDU(2, s7PlusOpResponse, 0x7777, 1, 1))).Plus; u == nil || u.FunctionName != "" || u.Function != 0x7777 {
		t.Errorf("unknown function keeps the number: %+v", u)
	}
	// Notification: opcode only, no request fields.
	n := MessageFromFrames(frame(s7PlusPDU(1, s7PlusOpNotification, 0, 0, 0))).Plus
	if n == nil || n.HasFields || n.OpcodeName != "Notification" {
		t.Errorf("%+v", n)
	}
	// Length field larger than the frame, and a bad trailer.
	bad := s7PlusPDU(1, s7PlusOpRequest, 0x04bb, 1, 0)
	bad[3] = 30 // just over the frame
	if m := MessageFromFrames(frame(bad)); !hasEvent(m.Events, S7PlusEventInvalid) {
		t.Errorf("events %v", m.Events)
	}
	bad = s7PlusPDU(1, s7PlusOpRequest, 0x04bb, 1, 0)
	bad[len(bad)-4] = 0
	if m := MessageFromFrames(frame(bad)); !hasEvent(m.Events, S7PlusEventInvalid) {
		t.Errorf("events %v", m.Events)
	}
	bad = s7PlusPDU(1, s7PlusOpRequest, 0x04bb, 1, 0)
	bad[len(bad)-3] = 2 // trailer version differs from the header
	if m := MessageFromFrames(frame(bad)); !hasEvent(m.Events, S7PlusEventInvalid) {
		t.Errorf("events %v", m.Events)
	}
}

func hasEvent(evs []string, e string) bool {
	for _, x := range evs {
		if x == e {
			return true
		}
	}
	return false
}

func TestS7TrackerPlus(t *testing.T) {
	tr := NewS7Tracker()
	cr := crFrame(false, []byte{0x01, 0x02}, []byte{0x01, 0x00})
	tr.FeedTCP("c", true, TCPSegment{Seq: 1, ACK: true, Payload: cr}, true)
	req := dtFrame(s7PlusPDU(1, s7PlusOpRequest, 0x04bb, 1, 0))
	ms := tr.FeedTCP("c", true, TCPSegment{Seq: 1 + uint32(len(cr)), ACK: true, Payload: req}, true)
	if len(ms) != 1 || ms[0].Plus == nil || ms[0].Slot != 2 {
		t.Fatalf("%+v", ms)
	}
	if !tr.SawS7Plus("c") || tr.SawS7("c") {
		t.Error("connection is S7CommPlus, not S7comm")
	}
	// Split over two segments.
	tr = NewS7Tracker()
	ms = tr.FeedTCP("c", true, TCPSegment{Seq: 1, ACK: true, Payload: req[:12]}, true)
	if len(ms) != 0 {
		t.Fatal("half frame")
	}
	ms = tr.FeedTCP("c", true, TCPSegment{Seq: 13, ACK: true, Payload: req[12:]}, true)
	if len(ms) != 1 || ms[0].Plus == nil {
		t.Fatalf("%+v", ms)
	}
}
