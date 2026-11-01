package detect

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// dnp3Frame builds a link frame with correct CRCs around user data.
func dnp3Frame(control byte, dest, src uint16, user []byte) []byte {
	h := []byte{0x05, 0x64, byte(5 + len(user)), control, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(h[4:], dest)
	binary.LittleEndian.PutUint16(h[6:], src)
	out := binary.LittleEndian.AppendUint16(h, dnp3CRC(h))
	for len(user) > 0 {
		n := min(len(user), 16)
		out = append(out, user[:n]...)
		out = binary.LittleEndian.AppendUint16(out, dnp3CRC(user[:n]))
		user = user[n:]
	}
	return out
}

// dnp3Segment is a frame holding one transport segment of app bytes.
func dnp3Segment(control byte, fir, fin bool, seq byte, app []byte) []byte {
	th := seq & 0x3f
	if fir {
		th |= 0x40
	}
	if fin {
		th |= 0x80
	}
	return dnp3Frame(control, 1, 2, append([]byte{th}, app...))
}

const (
	dnp3ToOutstation = 0xc4 // DIR PRM, unconfirmed user data
	dnp3ToMaster     = 0x44 // PRM, unconfirmed user data
)

// dnp3ReadClass0 is a Read request for class 0 data (g60v1, qualifier 06).
var dnp3ReadClass0 = []byte{0xc0, 0x01, 60, 1, 0x06}

func TestDNP3CRC(t *testing.T) {
	// From Suricata's probing parser test.
	hdr := []byte{0x05, 0x64, 0x05, 0xc9, 0x03, 0x00, 0x04, 0x00}
	if got := dnp3CRC(hdr); got != 0x71bd {
		t.Errorf("crc %#x, want 0x71bd", got)
	}
	if dnp3CRC([]byte("123456789")) != 0xea82 { // CRC-16/DNP check value
		t.Errorf("check value %#x", dnp3CRC([]byte("123456789")))
	}
}

func TestProbeDNP3(t *testing.T) {
	good := dnp3Segment(dnp3ToOutstation, true, true, 0, dnp3ReadClass0)
	cases := []struct {
		name string
		in   []byte
		want Result
	}{
		{"empty", nil, Incomplete},
		{"one start byte", good[:1], Incomplete},
		{"frame", good, Recognized},
		{"short header", good[:9], Incomplete},
		{"wrong second byte", []byte{5, 0x65, 5, 0xc4, 0, 0, 0, 0, 0, 0}, Unrecognized},
		{"wrong first byte", []byte("GET / HTTP/1.1\r\n"), Unrecognized},
		{"length 4", []byte{5, 0x64, 4, 0xc4, 0, 0, 0, 0, 0, 0}, Unrecognized},
		{"bad CRC is still DNP3", append([]byte{5, 0x64, 5, 0xc4, 1, 0, 2, 0}, 0, 0), Recognized},
	}
	for _, c := range cases {
		if got := ProbeDNP3(c.in); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	for i := range good {
		ProbeDNP3(good[:i])
	}
}

func TestParseDNP3Frame(t *testing.T) {
	user := make([]byte, 40) // three blocks: 16, 16, 8
	for i := range user {
		user[i] = byte(i)
	}
	b := dnp3Frame(dnp3ToOutstation, 10, 3, user)
	f, n, ok := ParseDNP3Frame(b)
	if !ok || n != len(b) || n != 10+40+6 {
		t.Fatalf("ok=%v n=%d len=%d", ok, n, len(b))
	}
	if !reflect.DeepEqual(f.UserData, user) || f.Dest != 10 || f.Src != 3 || !f.FromMaster() || !f.Primary() || f.LinkFunction() != 4 || len(f.Events) != 0 {
		t.Errorf("%+v", f)
	}
	if _, _, ok := ParseDNP3Frame(b[:len(b)-1]); ok {
		t.Error("incomplete frame must not parse")
	}
	bad := append([]byte(nil), b...)
	bad[8] ^= 1
	if f, _, _ := ParseDNP3Frame(bad); !hasEvent(f.Events, DNP3EventBadLinkCRC) {
		t.Errorf("events %v", f.Events)
	}
	bad = append([]byte(nil), b...)
	bad[10+18+2] ^= 1 // inside the second block
	if f, _, _ := ParseDNP3Frame(bad); !hasEvent(f.Events, DNP3EventBadTransportCRC) || hasEvent(f.Events, DNP3EventBadLinkCRC) {
		t.Errorf("events %v", f.Events)
	}
	// Header only (length 5): no user data, no blocks.
	h := dnp3Frame(0xc9, 1, 2, nil)
	if f, n, ok := ParseDNP3Frame(h); !ok || n != 10 || len(f.UserData) != 0 || f.Primary() == false {
		t.Errorf("%+v %d %v", f, n, ok)
	}
}

func TestDecodeDNP3App(t *testing.T) {
	a := decodeDNP3App(dnp3ReadClass0, true)
	if a.FunctionName != "Read" || !a.First() || !a.Final() || a.Sequence() != 0 || len(a.Objects) != 1 || !a.ObjectsComplete {
		t.Fatalf("%+v", a)
	}
	if o := a.Objects[0]; o.Group != 60 || o.Variation != 1 || o.Range != 6 {
		t.Errorf("%+v", o)
	}
	// Response with IIN and two binary inputs with flags (g2v1, 1-byte range 0-1).
	r := decodeDNP3App([]byte{0xc1, 0x81, 0x00, 0x80, 2, 1, 0x00, 0, 1, 0x81, 0x01}, false)
	if !r.IsResponse || r.IIN != 0x0080 || len(r.Objects) != 1 || !r.ObjectsComplete || r.Objects[0].Count != 2 || r.Objects[0].DataLen != 2 {
		t.Fatalf("%+v", r)
	}
	// Direct operate on a CROB (g12v1, count 1 byte with 1-byte index prefix 0x17).
	crob := append([]byte{0xc2, 0x05, 12, 1, 0x17, 1, 3}, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	op := decodeDNP3App(crob, true)
	if len(op.Objects) != 1 || op.Objects[0].DataLen != 12 || !op.ObjectsComplete || len(op.Events) != 0 {
		t.Fatalf("%+v", op)
	}
	// Packed binary inputs: count 10 is two bytes.
	p := decodeDNP3App([]byte{0xc1, 0x81, 0, 0, 1, 1, 0x00, 0, 9, 0xff, 0x01}, false)
	if len(p.Objects) != 1 || p.Objects[0].DataLen != 2 || !p.ObjectsComplete {
		t.Fatalf("%+v", p)
	}
	// Unknown object: header kept, event raised.
	u := decodeDNP3App([]byte{0xc1, 0x81, 0, 0, 99, 9, 0x07, 1, 0xaa}, false)
	if len(u.Objects) != 1 || u.ObjectsComplete || !hasEvent(u.Events, DNP3EventUnknownObject) {
		t.Fatalf("%+v", u)
	}
	// Cut short: range says 5 objects but data is missing.
	s := decodeDNP3App([]byte{0xc1, 0x81, 0, 0, 30, 1, 0x07, 5, 0, 1, 2}, false)
	if s.ObjectsComplete || !hasEvent(s.Events, DNP3EventMalformed) {
		t.Fatalf("%+v", s)
	}
	// Stop below start.
	if x := decodeDNP3App([]byte{0xc0, 0x01, 1, 2, 0x00, 5, 1}, true); x.ObjectsComplete || !hasEvent(x.Events, DNP3EventMalformed) {
		t.Fatalf("%+v", x)
	}
	if x := decodeDNP3App([]byte{0xc0}, true); !hasEvent(x.Events, DNP3EventMalformed) {
		t.Fatalf("%+v", x)
	}
	// Confirm has no objects.
	if c := decodeDNP3App([]byte{0xc0, 0x00}, true); c.FunctionName != "Confirm" || len(c.Objects) != 0 {
		t.Fatalf("%+v", c)
	}
	// 1-byte object size prefix (qualifier 0x47): two objects of 3 and 2 bytes. tshark
	// misreads this, so the demo capture leaves it out.
	if z := decodeDNP3App([]byte{0xc1, 0x81, 0, 0, 70, 3, 0x47, 2, 3, 'a', 'b', 'c', 2, 'd', 'e', 60, 1, 6}, false); len(z.Objects) != 2 || z.Objects[0].DataLen != 7 || !z.ObjectsComplete {
		t.Fatalf("%+v", z)
	}
	// Object-size prefix (qualifier 0x5b is variable; 0x4? uses 1-byte size prefix): g110 octet strings.
	o := decodeDNP3App([]byte{0xc1, 0x81, 0, 0, 110, 3, 0x07, 2, 'a', 'b', 'c', 'd', 'e', 'f'}, false)
	if len(o.Objects) != 1 || o.Objects[0].DataLen != 6 || !o.ObjectsComplete {
		t.Fatalf("%+v", o)
	}
}

func TestDNP3Tracker(t *testing.T) {
	const C, S = true, false
	feed := func(tr *DNP3Tracker, dir bool, seq uint32, p []byte) []DNP3Message {
		return tr.FeedTCP("c", dir, TCPSegment{Seq: seq, ACK: true, Payload: p}, true)
	}
	fc := func(ms []DNP3Message) (out []string) {
		for _, m := range ms {
			if m.App != nil {
				out = append(out, m.App.FunctionName)
			}
		}
		return
	}
	read := dnp3Segment(dnp3ToOutstation, true, true, 0, dnp3ReadClass0)

	t.Run("garbage makes no connection", func(t *testing.T) {
		tr := NewDNP3Tracker()
		feed(tr, C, 1, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		if tr.Len() != 0 || tr.Known("c") {
			t.Error("no state expected")
		}
	})
	t.Run("a frame recognises the connection", func(t *testing.T) {
		tr := NewDNP3Tracker()
		if got := fc(feed(tr, C, 1, read)); !reflect.DeepEqual(got, []string{"Read"}) || !tr.Known("c") {
			t.Errorf("%v", got)
		}
	})
	t.Run("two frames in one segment, one split in the header", func(t *testing.T) {
		tr := NewDNP3Tracker()
		two := append(append([]byte(nil), read...), dnp3Segment(dnp3ToOutstation, true, true, 1, []byte{0xc1, 0x0d})...)
		if got := fc(feed(tr, C, 1, two)); !reflect.DeepEqual(got, []string{"Read", "Cold Restart"}) {
			t.Errorf("%v", got)
		}
		tr = NewDNP3Tracker()
		if got := fc(feed(tr, C, 1, read[:4])); len(got) != 0 {
			t.Errorf("%v", got)
		}
		if got := fc(feed(tr, C, 5, read[4:])); !reflect.DeepEqual(got, []string{"Read"}) {
			t.Errorf("%v", got)
		}
	})
	t.Run("a fragment over three transport segments", func(t *testing.T) {
		tr := NewDNP3Tracker()
		// Response with 3 bytes of IIN-less header split over segments; app = c1 81 00 00 | g30v2 x3.
		app := []byte{0xc1, 0x81, 0, 0, 30, 2, 0x00, 0, 2, 0x01, 0, 0, 0x01, 1, 0, 0x01, 2, 0}
		var all []byte
		all = append(all, dnp3Segment(dnp3ToMaster, true, false, 5, app[:6])...)
		all = append(all, dnp3Segment(dnp3ToMaster, false, false, 6, app[6:12])...)
		all = append(all, dnp3Segment(dnp3ToMaster, false, true, 7, app[12:])...)
		ms := feed(tr, S, 1, all)
		if len(ms) != 3 || ms[0].App != nil || ms[1].App != nil || ms[2].App == nil {
			t.Fatalf("%+v", ms)
		}
		a := ms[2].App
		if a.FunctionName != "Response" || len(a.Objects) != 1 || a.Objects[0].Count != 3 || !a.ObjectsComplete || len(ms[2].Events) != 0 {
			t.Errorf("%+v events %v", a, ms[2].Events)
		}
	})
	t.Run("a lost transport segment drops the fragment", func(t *testing.T) {
		tr := NewDNP3Tracker()
		app := []byte{0xc1, 0x81, 0, 0}
		var all []byte
		all = append(all, dnp3Segment(dnp3ToMaster, true, false, 5, app)...)
		all = append(all, dnp3Segment(dnp3ToMaster, false, true, 7, nil)...) // 6 is missing
		ms := feed(tr, S, 1, all)
		if len(ms) != 2 || ms[1].App != nil || !hasEvent(ms[1].Events, DNP3EventMalformed) {
			t.Fatalf("%+v", ms)
		}
	})
	t.Run("an over-long fragment is dropped", func(t *testing.T) {
		tr := NewDNP3Tracker()
		chunk := make([]byte, 249)
		seq := uint32(1)
		var last []DNP3Message
		var events bool
		for i := 0; i < 300; i++ {
			fr := dnp3Segment(dnp3ToMaster, i == 0, i == 299, byte(i), chunk)
			last = feed(tr, S, seq, fr)
			seq += uint32(len(fr))
			events = events || (len(last) > 0 && hasEvent(last[0].Events, DNP3EventTooLongReass))
		}
		if !events || last[0].App != nil {
			t.Errorf("events=%v", events)
		}
	})
	t.Run("directions reassemble independently", func(t *testing.T) {
		tr := NewDNP3Tracker()
		first := dnp3Segment(dnp3ToMaster, true, false, 0, []byte{0xc1, 0x81, 0, 0})
		feed(tr, S, 1, first)
		// The client's request in between must not disturb the response.
		feed(tr, C, 1, read)
		ms := feed(tr, S, 1+uint32(len(first)), dnp3Segment(dnp3ToMaster, false, true, 1, nil))
		if len(ms) != 1 || ms[0].App == nil {
			t.Fatalf("%+v", ms)
		}
	})
	t.Run("bytes that are not a frame force a resync", func(t *testing.T) {
		tr := NewDNP3Tracker()
		feed(tr, C, 1, read)
		if got := fc(feed(tr, C, 1+uint32(len(read)), []byte("noise noise noise noise"))); len(got) != 0 {
			t.Errorf("%v", got)
		}
		next := 1 + uint32(len(read)) + 23
		if got := fc(feed(tr, C, next, read)); !reflect.DeepEqual(got, []string{"Read"}) {
			t.Errorf("%v", got)
		}
	})
	t.Run("segments arriving out of order are put in sequence", func(t *testing.T) {
		tr := NewDNP3Tracker()
		feed(tr, C, 1, read)
		second := dnp3Segment(dnp3ToOutstation, true, true, 1, []byte{0xc1, 0x0d})
		next := 1 + uint32(len(read))
		if got := fc(feed(tr, C, next+uint32(len(second)), read)); len(got) != 0 {
			t.Errorf("early segment must wait: %v", got)
		}
		if got := fc(feed(tr, C, next, second)); !reflect.DeepEqual(got, []string{"Cold Restart", "Read"}) {
			t.Errorf("%v", got)
		}
	})
	t.Run("retransmission is dropped", func(t *testing.T) {
		tr := NewDNP3Tracker()
		feed(tr, C, 1, read)
		if got := fc(feed(tr, C, 1, read)); len(got) != 0 {
			t.Errorf("%v", got)
		}
	})
	t.Run("connection limit", func(t *testing.T) {
		tr := NewDNP3TrackerLimit(1)
		tr.FeedTCP("a", true, TCPSegment{Seq: 1, ACK: true, Payload: read}, true)
		ms := tr.FeedTCP("b", true, TCPSegment{Seq: 1, ACK: true, Payload: read}, true)
		if tr.Len() != 1 || len(ms) != 1 || ms[0].App == nil {
			t.Errorf("len %d, %+v", tr.Len(), ms)
		}
	})
}

func TestDecodeDNP3Datagram(t *testing.T) {
	ms := DecodeDNP3Datagram(dnp3Segment(dnp3ToOutstation, true, true, 0, dnp3ReadClass0))
	if len(ms) != 1 || ms[0].App == nil || ms[0].App.FunctionName != "Read" {
		t.Fatalf("%+v", ms)
	}
	if DecodeDNP3Datagram([]byte("hello")) != nil {
		t.Error("not DNP3")
	}
}

func TestDNP3NeverPanicsOnTruncatedOrCorruptInput(t *testing.T) {
	var stream []byte
	stream = append(stream, dnp3Segment(dnp3ToOutstation, true, false, 0, []byte{0xc0, 0x01, 60, 1, 0x06, 1, 2, 3})...)
	stream = append(stream, dnp3Segment(dnp3ToOutstation, false, true, 1, []byte{4, 5})...)
	stream = append(stream, dnp3Segment(dnp3ToMaster, true, true, 2, []byte{0xc1, 0x81, 0, 0, 30, 1, 0, 0, 0, 1, 2, 0, 0, 0})...)
	for i := 0; i <= len(stream); i++ {
		ParseDNP3Frame(stream[:i])
		DecodeDNP3Datagram(stream[:i])
		tr := NewDNP3Tracker()
		tr.FeedTCP("c", true, TCPSegment{Seq: 1, ACK: true, Payload: stream[:i]}, true)
		tr.FeedTCP("c", true, TCPSegment{Seq: 1 + uint32(i), ACK: true, Payload: stream[i:]}, true)
	}
	for i := range stream { // every single-byte corruption
		b := append([]byte(nil), stream...)
		b[i] ^= 0xff
		tr := NewDNP3Tracker()
		tr.FeedTCP("c", true, TCPSegment{Seq: 1, ACK: true, Payload: b}, true)
		DecodeDNP3Datagram(b)
	}
}

func TestDNP3CRCErrorsLikeSuricata(t *testing.T) {
	read := dnp3Segment(dnp3ToOutstation, true, true, 0, dnp3ReadClass0)
	feed := func(tr *DNP3Tracker, seq uint32, p []byte) []DNP3Message {
		return tr.FeedTCP("c", true, TCPSegment{Seq: seq, ACK: true, Payload: p}, true)
	}
	apps := func(ms []DNP3Message) (n int) {
		for _, m := range ms {
			if m.App != nil {
				n++
			}
		}
		return
	}
	// A wrong header CRC: event, nothing decoded, and the next frame still parses (resync).
	bad := append([]byte(nil), read...)
	bad[8] ^= 1
	ms := feed(NewDNP3Tracker(), 1, append(append([]byte(nil), bad...), read...))
	if len(ms) != 2 || !hasEvent(ms[0].Events, DNP3EventBadLinkCRC) || !ms[0].Frame.Invalid || apps(ms) != 1 {
		t.Fatalf("%+v", ms)
	}
	// A wrong data block CRC: event, the frame's data is dropped.
	bad = append([]byte(nil), read...)
	bad[len(bad)-1] ^= 1
	ms = feed(NewDNP3Tracker(), 1, append(append([]byte(nil), bad...), read...))
	if len(ms) != 2 || !hasEvent(ms[0].Events, DNP3EventBadTransportCRC) || apps(ms) != 1 {
		t.Fatalf("%+v", ms)
	}
	// A frame start whose length is below 5, in the middle of a connection.
	tr := NewDNP3Tracker()
	feed(tr, 1, read)
	junk := []byte{5, 0x64, 4, 0xc4, 10, 0, 3, 0, 0, 0}
	ms = feed(tr, 1+uint32(len(read)), append(append([]byte(nil), junk...), read...))
	if len(ms) != 2 || !hasEvent(ms[0].Events, DNP3EventLenTooSmall) || apps(ms) != 1 {
		t.Fatalf("%+v", ms)
	}
	// Resync skips to the next start and keeps a trailing 0x05.
	if got := DNP3Resync([]byte{5, 0x64, 1, 2, 5, 0x64, 9}); got != 4 {
		t.Errorf("resync %d", got)
	}
	if got := DNP3Resync([]byte{5, 1, 2, 3, 5}); got != 4 {
		t.Errorf("resync keeps a final start byte: %d", got)
	}
	if got := DNP3Resync([]byte{5, 1, 2, 3}); got != 4 {
		t.Errorf("resync %d", got)
	}
}

func TestDNP3TrackerGapDropsPendingFragment(t *testing.T) {
	tr := NewDNP3Tracker()
	feed := func(seq uint32, p []byte) []DNP3Message {
		return tr.FeedTCP("c", false, TCPSegment{Seq: seq, ACK: true, Payload: p}, true)
	}
	first := dnp3Segment(dnp3ToMaster, true, false, 5, []byte{0xc1, 0x81, 0, 0})
	feed(1, first)
	seq := uint32(5000) // bytes were lost: the far segments force the stream past the hole
	junk := []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	for i := 0; i < 40; i++ {
		feed(seq, junk)
		seq += uint32(len(junk))
	}
	ms := feed(seq, dnp3Segment(dnp3ToMaster, false, true, 6, nil))
	if len(ms) != 1 || ms[0].App != nil {
		t.Fatalf("a fragment spanning lost bytes must not be decoded: %+v", ms)
	}
}

func TestDecodeDNP3AppMore(t *testing.T) {
	// Authentication response (131) has an IIN like any response.
	a := decodeDNP3App([]byte{0xc1, 0x83, 0x01, 0x02}, false)
	if !a.IsResponse || a.IIN != 0x0102 {
		t.Errorf("%+v", a)
	}
	// A read request lists ranges without data: g1v2 points 0 to 3, g30v1 points 0 to 1.
	r := decodeDNP3App([]byte{0xc1, 0x01, 1, 2, 0x00, 0, 3, 30, 1, 0x00, 0, 1}, true)
	if len(r.Objects) != 2 || !r.ObjectsComplete || len(r.Events) != 0 || r.Objects[0].Count != 4 || r.Objects[1].Count != 2 {
		t.Errorf("%+v", r)
	}
	// The same bytes in a response carry data, so the list is cut short.
	w := decodeDNP3App([]byte{0xc1, 0x81, 0, 0, 1, 2, 0x00, 0, 3, 30, 1, 0x00, 0, 1}, false)
	if w.ObjectsComplete {
		t.Errorf("%+v", w)
	}
}
