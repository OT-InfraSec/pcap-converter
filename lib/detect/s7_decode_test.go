package detect

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func be16(v ...uint16) []byte {
	var b []byte
	for _, x := range v {
		b = append(b, byte(x>>8), byte(x))
	}
	return b
}

func tpkt(b ...[]byte) []byte {
	body := cat(b...)
	return append([]byte{3, 0, byte((len(body) + 4) >> 8), byte(len(body) + 4)}, body...)
}

// dtFrame wraps an S7 PDU in COTP data (last fragment) and TPKT.
func dtFrame(s7 []byte) []byte { return tpkt([]byte{2, 0xf0, 0x80}, s7) }

// s7PDU builds an S7 PDU: header (10 bytes, 12 for Ack_Data), parameter, data.
func s7PDU(rosctr byte, ref uint16, param, data []byte, errs ...byte) []byte {
	h := []byte{0x32, rosctr, 0, 0}
	h = append(h, be16(ref, uint16(len(param)), uint16(len(data)))...)
	if rosctr == 2 || rosctr == 3 {
		e := []byte{0, 0}
		copy(e, errs)
		h = append(h, e...)
	}
	return cat(h, param, data)
}

func s7Item(area byte, db uint16, byteAddr, bit int, length uint16, size byte) []byte {
	addr := byteAddr*8 + bit
	return cat([]byte{0x12, 0x0a, 0x10, size}, be16(length, db), []byte{area, byte(addr >> 16), byte(addr >> 8), byte(addr)})
}

func crFrame(cc bool, dstTSAP, srcTSAP []byte) []byte {
	typ := byte(0xe0)
	if cc {
		typ = 0xd0
	}
	params := cat([]byte{0xc0, 1, 0x0a}, []byte{0xc1, byte(len(srcTSAP))}, srcTSAP, []byte{0xc2, byte(len(dstTSAP))}, dstTSAP)
	li := 6 + len(params)
	return tpkt([]byte{byte(li), typ, 0, 0, 0, 1, 0}, params)
}

func TestDecodeS7ConnectionRequest(t *testing.T) {
	f := crFrame(false, []byte{0x01, 0x02}, []byte{0x01, 0x00}) // rack 0, slot 2
	m, n, ok := DecodeS7(f)
	if !ok || n != len(f) {
		t.Fatalf("ok=%v n=%d", ok, n)
	}
	if m.COTPType != 0xe0 || m.COTPName != "CR" || m.HasS7 || m.Rack != 0 || m.Slot != 2 || m.TPDUSize != 1<<10 ||
		!reflect.DeepEqual(m.DstTSAP, []byte{1, 2}) || !reflect.DeepEqual(m.SrcTSAP, []byte{1, 0}) || len(m.Events) != 0 {
		t.Errorf("%+v", m)
	}
	cc, _, _ := DecodeS7(crFrame(true, []byte{1, 2}, []byte{1, 0}))
	if cc.COTPName != "CC" || !reflect.DeepEqual(cc.DstTSAP, []byte{1, 2}) || !reflect.DeepEqual(cc.SrcTSAP, []byte{1, 0}) || cc.Slot != 2 {
		t.Errorf("%+v", cc)
	}
	// Rack 1, slot 3: byte 2 of the TSAP is rack*32+slot.
	m, _, _ = DecodeS7(crFrame(false, []byte{0x03, 0x23}, []byte{0x01, 0x00}))
	if m.Rack != 1 || m.Slot != 3 {
		t.Errorf("rack %d slot %d", m.Rack, m.Slot)
	}
	// A TSAP that is not two bytes carries no rack and slot.
	m, _, _ = DecodeS7(crFrame(false, []byte("SIMATIC-ROOT-ES"), []byte{1, 0}))
	if m.Rack != -1 || m.Slot != -1 {
		t.Errorf("rack %d slot %d", m.Rack, m.Slot)
	}
}

func TestDecodeS7SetupCommunication(t *testing.T) {
	req := dtFrame(s7PDU(1, 1, []byte{0xf0, 0, 0, 1, 0, 1, 0x01, 0xe0}, nil))
	m, n, ok := DecodeS7(req)
	if !ok || n != len(req) || !m.HasS7 {
		t.Fatalf("%+v", m)
	}
	if m.ROSCTR != 1 || m.ROSCTRName != "Job" || m.PDURef != 1 || m.Function != 0xf0 || m.FunctionName != "Setup communication" ||
		m.Setup == nil || m.Setup.MaxAmQCalling != 1 || m.Setup.MaxAmQCalled != 1 || m.Setup.PDULength != 480 {
		t.Errorf("%+v", m)
	}
	resp, _, _ := DecodeS7(dtFrame(s7PDU(3, 1, []byte{0xf0, 0, 0, 1, 0, 1, 0x01, 0xe0}, nil, 0x81, 0x04)))
	if resp.ROSCTRName != "Ack_Data" || resp.ErrorClass != 0x81 || resp.ErrorCode != 4 || resp.Function != 0xf0 {
		t.Errorf("%+v", resp)
	}
}

func TestDecodeS7ReadVar(t *testing.T) {
	// Read DB1.DBW0 (2 bytes) and M4.2 (a bit) in one request.
	param := cat([]byte{0x04, 2}, s7Item(0x84, 1, 0, 0, 2, 2), s7Item(0x83, 0, 4, 2, 1, 1))
	m, _, ok := DecodeS7(dtFrame(s7PDU(1, 7, param, nil)))
	if !ok || m.Function != 0x04 || m.FunctionName != "Read Var" || len(m.Items) != 2 {
		t.Fatalf("%+v", m)
	}
	a, b := m.Items[0], m.Items[1]
	if a.Area != 0x84 || a.AreaName != "Data block" || a.DB != 1 || a.ByteAddress != 0 || a.Length != 2 || a.TransportSize != 2 ||
		a.TransportSizeName != "BYTE" || a.Syntax != 0x10 {
		t.Errorf("%+v", a)
	}
	if b.Area != 0x83 || b.AreaName != "Flags" || b.ByteAddress != 4 || b.Bit != 2 || b.TransportSize != 1 {
		t.Errorf("%+v", b)
	}

	// The reply: two data items. The first is 2 bytes and padded to even.
	data := cat([]byte{0xff, 4}, be16(16), []byte{0x12, 0x34}, []byte{0xff, 3}, be16(1), []byte{1})
	r, _, _ := DecodeS7(dtFrame(s7PDU(3, 7, []byte{0x04, 2}, data)))
	if len(r.Data) != 2 || r.Data[0].ReturnCode != 0xff || r.Data[0].ReturnName != "Success" || r.Data[0].Length != 16 ||
		!reflect.DeepEqual(r.Data[0].Bytes, []byte{0x12, 0x34}) || r.Data[1].Length != 1 || !reflect.DeepEqual(r.Data[1].Bytes, []byte{1}) {
		t.Errorf("%+v", r.Data)
	}
	// INT items count their length in bits; a one-byte item is followed by a fill byte.
	data = cat([]byte{0xff, 5}, be16(16), []byte{0, 7}, []byte{0xff, 2}, be16(1), []byte{9, 0}, []byte{0xff, 5}, be16(16), []byte{0, 8})
	r, _, ok = DecodeS7(dtFrame(s7PDU(3, 7, []byte{0x04, 3}, data)))
	if !ok || len(r.Data) != 3 || !reflect.DeepEqual(r.Data[0].Bytes, []byte{0, 7}) || !reflect.DeepEqual(r.Data[1].Bytes, []byte{9}) ||
		!reflect.DeepEqual(r.Data[2].Bytes, []byte{0, 8}) || len(r.Events) != 0 {
		t.Errorf("%+v events=%v", r.Data, r.Events)
	}
	// One or more stray bytes after complete items do not make the PDU invalid.
	r, _, _ = DecodeS7(dtFrame(s7PDU(3, 7, []byte{0x04, 1}, cat([]byte{0xff, 4}, be16(16), []byte{0x12, 0x34}, []byte{0}))))
	if len(r.Data) != 1 || len(r.Events) != 0 {
		t.Errorf("%+v events=%v", r.Data, r.Events)
	}
	// A data section too short for even one item is invalid.
	r, _, _ = DecodeS7(dtFrame(s7PDU(3, 7, []byte{0x04, 1}, []byte{0xff, 4})))
	if !reflect.DeepEqual(r.Events, []string{S7EventInvalidS7}) {
		t.Errorf("events=%v", r.Events)
	}
	// A data item with an error return code and no data.
	r, _, _ = DecodeS7(dtFrame(s7PDU(3, 8, []byte{0x04, 1}, []byte{0x0a, 0, 0, 0})))
	if len(r.Data) != 1 || r.Data[0].ReturnCode != 0x0a || r.Data[0].ReturnName != "Object does not exist" {
		t.Errorf("%+v", r.Data)
	}
}

func TestDecodeS7WriteVar(t *testing.T) {
	param := cat([]byte{0x05, 1}, s7Item(0x82, 0, 4, 2, 1, 1))
	data := cat([]byte{0, 3}, be16(1), []byte{1})
	m, _, _ := DecodeS7(dtFrame(s7PDU(1, 9, param, data)))
	if m.Function != 0x05 || m.FunctionName != "Write Var" || len(m.Items) != 1 || m.Items[0].Area != 0x82 ||
		m.Items[0].AreaName != "Outputs" || len(m.Data) != 1 || !reflect.DeepEqual(m.Data[0].Bytes, []byte{1}) {
		t.Errorf("%+v", m)
	}
	// The reply carries return codes only.
	r, _, _ := DecodeS7(dtFrame(s7PDU(3, 9, []byte{0x05, 1}, []byte{0xff})))
	if len(r.Data) != 1 || r.Data[0].ReturnCode != 0xff {
		t.Errorf("%+v", r.Data)
	}
}

func TestDecodeS7PLCControl(t *testing.T) {
	stop := cat([]byte{0x29, 0, 0, 0, 0, 0, 9}, []byte("P_PROGRAM"))
	m, _, _ := DecodeS7(dtFrame(s7PDU(1, 3, stop, nil)))
	if m.Function != 0x29 || m.FunctionName != "PLC Stop" || m.PLCService != "P_PROGRAM" {
		t.Errorf("%+v", m)
	}
	start := cat([]byte{0x28, 0, 0, 0, 0, 0, 0, 0xfd}, be16(0), []byte{9}, []byte("P_PROGRAM"))
	m, _, _ = DecodeS7(dtFrame(s7PDU(1, 4, start, nil)))
	if m.Function != 0x28 || m.FunctionName != "PLC Control" || m.PLCService != "P_PROGRAM" {
		t.Errorf("%+v", m)
	}
	for fc, name := range map[byte]string{0x1a: "Request download", 0x1b: "Download block", 0x1c: "Download ended",
		0x1d: "Start upload", 0x1e: "Upload", 0x1f: "End upload", 0x00: "CPU services"} {
		m, _, _ := DecodeS7(dtFrame(s7PDU(1, 5, []byte{fc, 0, 0, 0}, nil)))
		if m.FunctionName != name {
			t.Errorf("function %#x = %q, want %q", fc, m.FunctionName, name)
		}
	}
	m, _, _ = DecodeS7(dtFrame(s7PDU(1, 5, []byte{0x77}, nil)))
	if m.FunctionName != "unknown-119" || len(m.Events) != 0 {
		t.Errorf("%+v", m)
	}
}

func userdata(typ, group, sub, seq byte, long bool, data []byte) []byte {
	p := []byte{0, 1, 0x12, 4, 0x11, typ<<4 | group, sub, seq}
	if long {
		p[3] = 8
		p = append(p, 0, 0, 0, 0)
	}
	return s7PDU(7, 11, p, data)
}

func TestDecodeS7Userdata(t *testing.T) {
	// Read SZL 0x001C index 1.
	req := userdata(4, 4, 1, 0, false, cat([]byte{0xff, 9}, be16(4, 0x1c, 1)))
	m, _, ok := DecodeS7(dtFrame(req))
	if !ok || m.Userdata == nil {
		t.Fatalf("%+v", m)
	}
	u := m.Userdata
	if len(m.Data) != 1 || m.Data[0].ReturnCode != 0xff || m.Data[0].TransportSize != 9 || m.Data[0].Length != 4 {
		t.Errorf("userdata data item: %+v", m.Data)
	}
	if m.ROSCTRName != "Userdata" || u.Type != 4 || u.TypeName != "Request" || u.FunctionGroup != 4 || u.FunctionGroupName != "CPU functions" ||
		u.SubFunction != 1 || u.SubFunctionName != "Read SZL" || u.SZLID != 0x1c || u.SZLIndex != 1 {
		t.Errorf("%+v", u)
	}
	for g, name := range map[byte]string{1: "Programmer commands", 2: "Cyclic data", 3: "Block functions", 4: "CPU functions",
		5: "Security", 6: "PBC BSEND/BRECV", 7: "Time functions"} {
		m, _, _ := DecodeS7(dtFrame(userdata(4, g, 1, 0, false, []byte{0x0a, 0, 0, 0})))
		if m.Userdata.FunctionGroupName != name {
			t.Errorf("group %d = %q", g, m.Userdata.FunctionGroupName)
		}
	}
}

func padName(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}

func TestDecodeS7UserdataLongParameter(t *testing.T) {
	// A reply in two data units: data unit reference 5, last data unit 1, error 0x8104.
	p := []byte{0, 1, 0x12, 8, 0x12, 0x84, 1, 3, 5, 1, 0x81, 0x04}
	m, _, _ := DecodeS7(dtFrame(s7PDU(7, 1, p, []byte{0x0a, 0, 0, 0})))
	u := m.Userdata
	if u == nil || u.Type != 8 || u.FunctionGroup != 4 || u.Sequence != 3 || u.DataUnitRef != 5 || u.LastDataUnit != 1 || u.ErrorCode != 0x8104 {
		t.Errorf("%+v", u)
	}
}

func TestDecodeS7SZLIdentity(t *testing.T) {
	// SZL 0x001C: records of an index and a 32-byte string.
	rec := func(idx uint16, s string) []byte { return cat(be16(idx), padName(s, 32)) }
	recs := cat(rec(1, "S7-1200 station_1"), rec(2, "CPU 1214C DC/DC/DC"), rec(3, "Plant A"), rec(4, "Original Siemens Equipment"),
		rec(5, "S C-ABC123456"), rec(7, "CPU 1214C"))
	body := cat(be16(0x1c, 0), be16(34, 6), recs)
	data := cat([]byte{0xff, 9}, be16(uint16(len(body))), body)
	m, _, ok := DecodeS7(dtFrame(userdata(8, 4, 1, 0, true, data)))
	if !ok || m.Userdata == nil || m.Userdata.Identity == nil {
		t.Fatalf("%+v", m.Userdata)
	}
	id := m.Userdata.Identity
	want := map[uint16]string{1: "S7-1200 station_1", 2: "CPU 1214C DC/DC/DC", 3: "Plant A", 4: "Original Siemens Equipment", 5: "S C-ABC123456", 7: "CPU 1214C"}
	if !reflect.DeepEqual(id.Strings, want) || m.Userdata.SZLID != 0x1c || m.Userdata.TypeName != "Response" {
		t.Errorf("%+v", id)
	}

	// SZL 0x0011: index, 20-byte order number, module type, two version words.
	rec11 := cat(be16(7), padName("6ES7 214-1AG40-0XB0", 20), be16(0x0101, 0x0002, 0x0301))
	body = cat(be16(0x11, 0), be16(28, 1), rec11)
	data = cat([]byte{0xff, 9}, be16(uint16(len(body))), body)
	m, _, _ = DecodeS7(dtFrame(userdata(8, 4, 1, 0, true, data)))
	if m.Userdata == nil || m.Userdata.Identity == nil || m.Userdata.Identity.OrderNumber != "6ES7 214-1AG40-0XB0" ||
		m.Userdata.Identity.ModuleType != 0x0101 || m.Userdata.Identity.Version != [2]uint16{2, 0x0301} {
		t.Errorf("%+v", m.Userdata)
	}
}

func TestDecodeS7Invalid(t *testing.T) {
	tests := []struct {
		name string
		pdu  []byte
	}{
		{"parameter longer than the PDU", []byte{0x32, 1, 0, 0, 0, 1, 0, 50, 0, 0}},
		{"read var with fewer items than counted", dtPayload(s7PDU(1, 1, cat([]byte{4, 2}, s7Item(0x84, 1, 0, 0, 2, 2)), nil))},
		{"read var item with the wrong spec length", dtPayload(s7PDU(1, 1, cat([]byte{4, 1}, []byte{0x12, 0x05, 0x10, 2, 0, 1, 0}), nil))},
		{"setup communication too short", dtPayload(s7PDU(1, 1, []byte{0xf0, 0, 0}, nil))},
		{"userdata parameter too short", dtPayload(s7PDU(7, 1, []byte{0, 1, 0x12}, nil))},
		{"userdata parameter shorter than its length byte says", dtPayload(s7PDU(7, 1, []byte{0, 1, 0x12, 8, 0x11, 0x44, 1, 0}, nil))},
		{"data item longer than the data", dtPayload(s7PDU(3, 1, []byte{4, 1}, cat([]byte{0xff, 4}, be16(160), []byte{1, 2})))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, ok := DecodeS7(dtFrame(tc.pdu))
			if !ok {
				t.Fatal("the frame itself is complete")
			}
			if !m.HasS7 || !reflect.DeepEqual(m.Events, []string{S7EventInvalidS7}) {
				t.Errorf("events = %v", m.Events)
			}
		})
	}
}

func dtPayload(b []byte) []byte { return b }

// An invalid PDU still reports what decoded before the failure.
func TestDecodeS7InvalidKeepsPartialItems(t *testing.T) {
	two := cat([]byte{4, 2}, s7Item(0x84, 1, 0, 0, 2, 2)) // two items counted, one present
	m, _, _ := DecodeS7(dtFrame(s7PDU(1, 5, two, nil)))
	if len(m.Items) != 1 || m.Items[0].DB != 1 || !reflect.DeepEqual(m.Events, []string{S7EventInvalidS7}) {
		t.Errorf("%+v", m)
	}
	data := cat([]byte{0xff, 4}, be16(16), []byte{1, 2}, []byte{0xff, 4}, be16(160), []byte{1})
	m, _, _ = DecodeS7(dtFrame(s7PDU(3, 5, []byte{4, 2}, data)))
	if len(m.Data) != 1 || !reflect.DeepEqual(m.Events, []string{S7EventInvalidS7}) {
		t.Errorf("%+v", m)
	}
}

func TestDecodeS7Framing(t *testing.T) {
	f := dtFrame(s7PDU(1, 1, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil))
	if _, _, ok := DecodeS7(f[:3]); ok {
		t.Error("less than a TPKT header")
	}
	if _, _, ok := DecodeS7(f[:len(f)-1]); ok {
		t.Error("incomplete frame")
	}
	_, n, ok := DecodeS7(append(append([]byte(nil), f...), 1, 2, 3))
	if !ok || n != len(f) {
		t.Errorf("only the first frame is consumed: %v %d", ok, n)
	}
	if got := S7FrameSize(f[:4]); got != len(f) {
		t.Errorf("S7FrameSize = %d", got)
	}
	if S7FrameSize([]byte{2, 0, 0, 10}) != -1 {
		t.Error("version 2 is not TPKT")
	}
	if S7FrameSize([]byte{3, 0, 0, 3}) != -1 {
		t.Error("TPKT length below the header size")
	}
	// A frame whose COTP length does not fit the TPKT length, with an even and
	// an odd body length.
	for _, body := range [][]byte{{20, 0xf0}, {20, 0xf0, 0x80, 7}, {0, 0xf0}} {
		if m, _, ok := DecodeS7(tpkt(body)); !ok || !reflect.DeepEqual(m.Events, []string{S7EventInvalidCOTP}) || m.COTPName != "DT" {
			t.Errorf("body %v: %+v", body, m)
		}
	}
	bad := tpkt([]byte{20, 0xf0, 0x80})
	m, _, ok := DecodeS7(bad)
	if !ok || !reflect.DeepEqual(m.Events, []string{S7EventInvalidCOTP}) {
		t.Errorf("%+v", m)
	}
	// COTP types without S7 data.
	for typ, name := range map[byte]string{0x80: "DR", 0xc0: "DC", 0x70: "ER"} {
		m, _, _ := DecodeS7(tpkt([]byte{6, typ, 0, 1, 0, 2, 0}))
		if m.COTPName != name || m.HasS7 {
			t.Errorf("%#x: %+v", typ, m)
		}
	}
	// DT carrying something that is not S7 (MMS starts with a session layer).
	m, _, _ = DecodeS7(dtFrame([]byte{0x01, 0x00, 0x01, 0x00, 0x61, 0x02}))
	if m.HasS7 || m.COTPName != "DT" || len(m.Events) != 0 {
		t.Errorf("%+v", m)
	}
}

func TestDecodeS7FragmentedDT(t *testing.T) {
	// A COTP DT without the EOT bit: the S7 PDU continues in the next frame.
	pdu := s7PDU(1, 1, cat([]byte{4, 1}, s7Item(0x84, 1, 0, 0, 2, 2)), nil)
	first := tpkt([]byte{2, 0xf0, 0x00}, pdu[:9])
	rest := tpkt([]byte{2, 0xf0, 0x80}, pdu[9:])
	f1, n, ok := ParseS7Frame(first)
	if !ok || n != len(first) || f1.EOT || f1.COTPType != 0xf0 {
		t.Fatalf("%+v", f1)
	}
	f2, _, _ := ParseS7Frame(rest)
	if !f2.EOT {
		t.Fatal("last fragment")
	}
	m := MessageFromFrames([]S7Frame{f1, f2})
	if !m.HasS7 || m.Function != 4 || len(m.Items) != 1 {
		t.Errorf("%+v", m)
	}
}

func TestProbeS7(t *testing.T) {
	setup := dtFrame(s7PDU(1, 1, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil))
	tests := []struct {
		name string
		in   []byte
		want Result
	}{
		{"empty", nil, Incomplete},
		{"short", setup[:6], Incomplete},
		{"COTP data header only", setup[:8], Incomplete},
		{"S7 job", setup, Recognized},
		{"S7 job, first 12 bytes only", setup[:12], Recognized},
		{"connection request: undecided", crFrame(false, []byte{1, 2}, []byte{1, 0}), Incomplete},
		{"connection confirm: undecided", crFrame(true, []byte{1, 2}, []byte{1, 0}), Incomplete},
		{"MMS over COTP", dtFrame([]byte{0x01, 0x01, 0x01, 0x00, 0x61, 0x02, 0x02, 0x01}), Unrecognized},
		{"not TPKT", []byte("GET / HTTP/1.1\r\nHost: x\r\n"), Unrecognized},
		{"TPKT version 2", append([]byte{2, 0, 0, 12}, setup[4:]...), Unrecognized},
		{"S7 with an unknown ROSCTR", dtFrame(s7PDU(9, 1, nil, nil)), Unrecognized},
		{"TPKT length too small", []byte{3, 0, 0, 5, 2, 0xf0, 0x80, 0x32}, Unrecognized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProbeS7(tc.in); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	_ = binary.BigEndian
}

func FuzzDecodeS7(f *testing.F) {
	f.Add(dtFrame(s7PDU(1, 1, []byte{0xf0, 0, 0, 1, 0, 1, 1, 0xe0}, nil)))
	f.Add(crFrame(false, []byte{1, 2}, []byte{1, 0}))
	f.Add(dtFrame(userdata(8, 4, 1, 0, true, cat([]byte{0xff, 9}, be16(10), be16(0x1c, 0, 34, 1)))))
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, n, ok := DecodeS7(b); ok && (n < 4 || n > len(b) || m.COTPName == "") {
			t.Fatalf("n=%d %+v", n, m)
		}
		ProbeS7(b)
		S7FrameSize(b)
	})
}
