package detect

import (
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func le16(v ...uint16) []byte {
	var b []byte
	for _, x := range v {
		b = append(b, byte(x), byte(x>>8))
	}
	return b
}

// enipPDU builds an encapsulation message: the 24-byte header and data.
func enipPDU(cmd uint16, session, status uint32, data []byte) []byte {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint16(h[0:], cmd)
	binary.LittleEndian.PutUint16(h[2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(h[4:], session)
	binary.LittleEndian.PutUint32(h[8:], status)
	return append(h, data...)
}

// rrData wraps a CIP message in a SendRRData payload: unconnected message.
func rrData(cip []byte) []byte {
	d := []byte{0, 0, 0, 0, 0, 0} // interface handle, timeout
	d = append(d, le16(2)...)     // two items
	d = append(d, le16(0, 0)...)  // null address item
	d = append(d, le16(0xb2, uint16(len(cip)))...)
	return append(d, cip...)
}

// Real payloads from the minicps testbed (m13e880-br-seg*.pcap).
const (
	realRegisterReq   = "65000400000000000000000000000000000000000000000001000000"
	realRegisterResp  = "65000400010000000000000000000000000000000000000001000000"
	realGetAttrSingle = "6f0018000100000000000000020000000000000000000000000000000000020000000000b20008000e03200424013003"
	realGetAttrResp   = "6f0016000100000000000000020000000000000000000000000000000000020000000000b20006008e0000003200"
	realForwardOpen   = "6f0042000300000000000000020000000000000000000000000000000000020000000000b20032005402200624010a0e0000000001009d154f7500004ef5dea602000000a08601000248a08601000e480104200424972cc62c64"
	realForwardOpenNo = "6f001e000300000000000000020000000000000000000000000000000000020000000000b2000e00d4000200517500004ef5dea60000"
	realGetAttrList   = "6f0024000200000000000000020000000000000000000000000000000000020000000000b20014000302200424010600060005000100030002000400"
	realSetAttrSingle = "6f001a000600000000000000020000000000000000000000000000000000020000000000b2000a0010032004240130033c00"
	realForwardClose  = "6f002a000900000000000000020000000000000000000000000000000000020000000000b2001a004e02200624010a0e557500004ef5dea60400200424972cc62c64"
)

func TestDecodeENIPRealMessages(t *testing.T) {
	t.Run("register session", func(t *testing.T) {
		m, n, ok := DecodeENIP(unhex(t, realRegisterReq))
		if !ok || n != 28 {
			t.Fatalf("ok=%v n=%d", ok, n)
		}
		if m.Command != ENIPRegisterSession || m.CommandName != "register_session" || m.Status != 0 || m.StatusName != "success" ||
			m.RegisterSession == nil || m.RegisterSession.ProtocolVersion != 1 || m.RegisterSession.Options != 0 || m.Invalid {
			t.Errorf("%+v", m)
		}
		r, _, _ := DecodeENIP(unhex(t, realRegisterResp))
		if r.Session != 1 {
			t.Errorf("session = %d", r.Session)
		}
	})
	t.Run("get attribute single", func(t *testing.T) {
		m, _, ok := DecodeENIP(unhex(t, realGetAttrSingle))
		if !ok || m.CIP == nil {
			t.Fatalf("%+v", m)
		}
		c := m.CIP
		if m.CommandName != "send_r_r_data" || c.Service != 0x0e || c.IsResponse || c.Class != 4 || c.Instance != 1 || c.Attribute != 3 ||
			c.ServiceName != "Get Attribute Single" || len(c.Path) != 3 {
			t.Errorf("%+v", c)
		}
		if c.Path[0].Kind != "class" || c.Path[1].Kind != "instance" || c.Path[2].Kind != "attribute" {
			t.Errorf("path %+v", c.Path)
		}
	})
	t.Run("get attribute single response", func(t *testing.T) {
		m, _, _ := DecodeENIP(unhex(t, realGetAttrResp))
		c := m.CIP
		if c == nil || !c.IsResponse || c.Service != 0x0e || c.GeneralStatus != 0 || c.GeneralStatusName != "Success" {
			t.Errorf("%+v", c)
		}
	})
	t.Run("forward open is named by its class", func(t *testing.T) {
		m, _, _ := DecodeENIP(unhex(t, realForwardOpen))
		c := m.CIP
		if c == nil || c.Service != 0x54 || c.Class != 6 || c.Instance != 1 || c.ServiceName != "Forward Open" {
			t.Errorf("%+v", c)
		}
		r, _, _ := DecodeENIP(unhex(t, realForwardOpenNo))
		if r.CIP == nil || r.CIP.Service != 0x54 || r.CIP.GeneralStatus != 2 || r.CIP.GeneralStatusName != "Resource Unavailable" {
			t.Errorf("%+v", r.CIP)
		}
	})
	t.Run("service 0x4E in the connection manager is Forward Close", func(t *testing.T) {
		m, _, _ := DecodeENIP(unhex(t, realForwardClose))
		if m.CIP == nil || m.CIP.Service != 0x4e || m.CIP.Class != 6 || m.CIP.ServiceName != "Forward Close" {
			t.Errorf("%+v", m.CIP)
		}
	})
	t.Run("get attribute list", func(t *testing.T) {
		m, _, _ := DecodeENIP(unhex(t, realGetAttrList))
		if m.CIP == nil || m.CIP.Service != 3 || !reflect.DeepEqual(m.CIP.AttributeList, []uint16{6, 5, 1, 3, 2, 4}) {
			t.Errorf("%+v", m.CIP)
		}
	})
	t.Run("set attribute single", func(t *testing.T) {
		m, _, _ := DecodeENIP(unhex(t, realSetAttrSingle))
		if m.CIP == nil || m.CIP.Service != 0x10 || m.CIP.Attribute != 3 || m.CIP.ServiceName != "Set Attribute Single" {
			t.Errorf("%+v", m.CIP)
		}
	})
}

func TestDecodeENIPFraming(t *testing.T) {
	full := unhex(t, realGetAttrSingle)
	if _, _, ok := DecodeENIP(full[:23]); ok {
		t.Error("less than a header")
	}
	if _, _, ok := DecodeENIP(full[:len(full)-1]); ok {
		t.Error("incomplete PDU")
	}
	_, n, ok := DecodeENIP(append(append([]byte(nil), full...), 1, 2, 3))
	if !ok || n != len(full) {
		t.Errorf("only the first PDU is consumed: ok=%v n=%d", ok, n)
	}
	if got := ENIPPDUSize(full[:24]); got != len(full) {
		t.Errorf("ENIPPDUSize = %d", got)
	}
}

func TestDecodeENIPListIdentity(t *testing.T) {
	sock := []byte{0, 2, 0xaf, 0x12, 10, 1, 1, 22, 0, 0, 0, 0, 0, 0, 0, 0} // AF_INET, port 44818, 10.1.1.22
	name := []byte("1756-ENBT/A")
	item := append(le16(1), sock...)
	item = append(item, le16(1, 12, 0x36)...)   // vendor, device type, product code
	item = append(item, 5, 1)                   // revision 5.1
	item = append(item, le16(0x30)...)          // status
	item = append(item, 0x78, 0x56, 0x34, 0x12) // serial
	item = append(item, byte(len(name)))
	item = append(item, name...)
	item = append(item, 3) // state
	data := append(le16(1), le16(0x0c, uint16(len(item)))...)
	data = append(data, item...)

	m, _, ok := DecodeENIP(enipPDU(ENIPListIdentity, 0, 0, data))
	if !ok || m.Invalid || len(m.Items) != 1 || m.Items[0].Identity == nil {
		t.Fatalf("%+v", m)
	}
	id := m.Items[0].Identity
	want := ENIPIdentity{ProtocolVersion: 1, IP: "10.1.1.22", Port: 44818, VendorID: 1, DeviceType: 12, ProductCode: 0x36,
		RevisionMajor: 5, RevisionMinor: 1, Status: 0x30, Serial: 0x12345678, ProductName: "1756-ENBT/A", State: 3}
	if *id != want {
		t.Errorf("got  %+v\nwant %+v", *id, want)
	}
	// An empty request carries no items.
	req, _, ok := DecodeENIP(enipPDU(ENIPListIdentity, 0, 0, nil))
	if !ok || req.Invalid || len(req.Items) != 0 {
		t.Errorf("%+v", req)
	}
}

func TestDecodeENIPListServices(t *testing.T) {
	item := append(le16(1, 0x0120), []byte("Communications\x00\x00")...)
	data := append(le16(1), le16(0x100, uint16(len(item)))...)
	data = append(data, item...)
	m, _, _ := DecodeENIP(enipPDU(ENIPListServices, 0, 0, data))
	if len(m.Items) != 1 || m.Items[0].Services == nil {
		t.Fatalf("%+v", m)
	}
	s := m.Items[0].Services
	if s.ProtocolVersion != 1 || s.Capabilities != 0x0120 || s.Name != "Communications" {
		t.Errorf("%+v", s)
	}
}

func TestDecodeENIPInvalidPayloads(t *testing.T) {
	tests := []struct {
		name string
		pdu  []byte
	}{
		{"register session too short", enipPDU(ENIPRegisterSession, 0, 0, []byte{1, 0})},
		{"item count larger than the data", enipPDU(ENIPListIdentity, 0, 0, le16(5))},
		{"item longer than the data", enipPDU(ENIPListIdentity, 0, 0, append(le16(1, 0x0c, 200), 1, 2))},
		{"identity item too short", enipPDU(ENIPListIdentity, 0, 0, append(le16(1, 0x0c, 4), 1, 0, 0, 0))},
		{"services item too short", enipPDU(ENIPListServices, 0, 0, append(le16(1, 0x100, 2), 1, 0))},
		{"send RR data without items", enipPDU(ENIPSendRRData, 1, 0, []byte{0, 0, 0, 0, 0, 0})},
		{"CIP item without a service byte", enipPDU(ENIPSendRRData, 1, 0, rrData(nil))},
		{"CIP path longer than the data", enipPDU(ENIPSendRRData, 1, 0, rrData([]byte{0x0e, 9, 0x20, 4}))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _, ok := DecodeENIP(tc.pdu)
			if !ok {
				t.Fatal("the frame itself is complete")
			}
			if !m.Invalid || !reflect.DeepEqual(m.Events, []string{ENIPEventInvalidPDU}) {
				t.Errorf("invalid=%v events=%v", m.Invalid, m.Events)
			}
		})
	}
}

func TestDecodeENIPCommandsWithoutDecodedPayload(t *testing.T) {
	for _, cmd := range []uint16{ENIPNop, ENIPUnregisterSession, ENIPIndicateStatus, ENIPCancel, 0x7777} {
		m, n, ok := DecodeENIP(enipPDU(cmd, 1, 0, []byte{1, 2, 3, 4}))
		if !ok || n != 28 || m.Invalid || m.CIP != nil || len(m.Items) != 0 {
			t.Errorf("cmd %#x: %+v", cmd, m)
		}
	}
	m, _, _ := DecodeENIP(enipPDU(0x7777, 1, 0x1234, nil))
	if m.CommandName != "unknown-30583" || m.StatusName != "unknown-4660" {
		t.Errorf("names %q %q", m.CommandName, m.StatusName)
	}
}

func TestDecodeENIPCIPDetails(t *testing.T) {
	pathClassInstAttr16 := []byte{0x21, 0, 0x34, 0x12, 0x25, 0, 0x78, 0x56, 0x31, 0, 0x09, 0x00} // 16-bit formats
	cip := func(b ...byte) *CIPMessage {
		m, _, ok := DecodeENIP(enipPDU(ENIPSendRRData, 1, 0, rrData(b)))
		if !ok || m.CIP == nil {
			t.Fatalf("not decoded: %+v", m)
		}
		return m.CIP
	}
	t.Run("16-bit path segments", func(t *testing.T) {
		c := cip(append([]byte{0x0e, 6}, pathClassInstAttr16...)...)
		if c.Class != 0x1234 || c.Instance != 0x5678 || c.Attribute != 9 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("32-bit class", func(t *testing.T) {
		c := cip(0x0e, 4, 0x22, 0, 1, 2, 3, 4, 0x24, 1)
		if c.Class != 0x04030201 || c.Instance != 1 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("no attribute in the path", func(t *testing.T) {
		c := cip(0x01, 2, 0x20, 1, 0x24, 1)
		if c.Class != 1 || c.Instance != 1 || c.Attribute != -1 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("ANSI symbolic segment (a Logix tag)", func(t *testing.T) {
		c := cip(0x4c, 3, 0x91, 4, 'T', 'a', 'g', '1', 1, 0)
		if c.Symbol != "Tag1" || c.Service != 0x4c || c.PathTruncated {
			t.Errorf("%+v", c)
		}
	})
	t.Run("an unknown segment type is not an invalid PDU", func(t *testing.T) {
		m, _, _ := DecodeENIP(enipPDU(ENIPSendRRData, 1, 0, rrData([]byte{0x0e, 2, 0x01, 0x02, 0x20, 4})))
		if m.Invalid || m.CIP == nil || !m.CIP.PathTruncated {
			t.Errorf("%+v", m.CIP)
		}
	})
	t.Run("extended status counts words", func(t *testing.T) {
		// Forward Open error with one extended status word 0x0109, then data.
		c := cip(0xd4, 0, 1, 1, 0x09, 0x01, 0xaa, 0xbb)
		if !c.IsResponse || c.GeneralStatus != 1 || !reflect.DeepEqual(c.ExtendedStatus, []uint16{0x0109}) {
			t.Errorf("%+v", c)
		}
	})
	t.Run("set attribute list reports the first attribute", func(t *testing.T) {
		c := cip(0x04, 2, 0x20, 4, 0x24, 1, 2, 0, 7, 0, 1, 2, 3)
		if c.FirstAttribute != 7 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("multiple service packet", func(t *testing.T) {
		one := []byte{0x0e, 2, 0x20, 1, 0x24, 1}          // get attribute single of class 1
		two := []byte{0x0e, 3, 0x20, 4, 0x24, 1, 0x30, 3} // and of class 4
		hdr := 2 + 2*2
		body := append(le16(2, uint16(hdr), uint16(hdr+len(one))), append(append([]byte(nil), one...), two...)...)
		c := cip(append([]byte{0x0a, 2, 0x20, 2, 0x24, 1}, body...)...)
		if c.Service != 0x0a || len(c.Multiple) != 2 || c.Multiple[0].Class != 1 || c.Multiple[1].Attribute != 3 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("multiple service response", func(t *testing.T) {
		r1 := []byte{0x8e, 0, 0, 0, 0xaa, 0xbb}
		r2 := []byte{0x8e, 0, 5, 0}
		hdr := 2 + 2*2
		body := append(le16(2, uint16(hdr), uint16(hdr+len(r1))), append(append([]byte(nil), r1...), r2...)...)
		c := cip(append([]byte{0x8a, 0, 0, 0}, body...)...)
		if !c.IsResponse || len(c.Multiple) != 2 || c.Multiple[1].GeneralStatus != 5 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("nested multiple service packets are not followed", func(t *testing.T) {
		inner := []byte{0x0a, 0}
		body := append(le16(1, 4), inner...)
		c := cip(append([]byte{0x0a, 0}, body...)...)
		if len(c.Multiple) != 1 || len(c.Multiple[0].Multiple) != 0 {
			t.Errorf("%+v", c)
		}
	})
}

func TestDecodeENIPConnectedData(t *testing.T) {
	// SendUnitData: connected address item (connection id) and connected data
	// item (sequence number, then CIP).
	cipb := []byte{0x0e, 2, 0x20, 1, 0x24, 1}
	d := []byte{0, 0, 0, 0, 0, 0}
	d = append(d, le16(2)...)
	d = append(d, le16(0xa1, 4)...)
	d = append(d, 0xef, 0xbe, 0xad, 0xde)
	d = append(d, le16(0xb1, uint16(2+len(cipb)))...)
	d = append(d, le16(77)...)
	d = append(d, cipb...)
	m, _, _ := DecodeENIP(enipPDU(ENIPSendUnitData, 1, 0, d))
	if m.CIP == nil || m.CIP.Service != 0x0e || m.CIP.Class != 1 || m.CIP.Sequence == nil || *m.CIP.Sequence != 77 {
		t.Fatalf("%+v", m.CIP)
	}
}

func FuzzDecodeENIP(f *testing.F) {
	for _, h := range []string{realRegisterReq, realGetAttrSingle, realForwardOpen, realGetAttrList} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, n, ok := DecodeENIP(b); ok && (n < 24 || n > len(b) || m.Command > 0xffff) {
			t.Fatalf("n=%d", n)
		}
	})
}
