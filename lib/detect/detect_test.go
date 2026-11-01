package detect

import (
	"encoding/binary"
	"testing"
)

// enipHeader builds a 24-byte encapsulation header plus body.
func enipHeader(cmd uint16, length uint16, status uint32, options uint32, body []byte) []byte {
	b := make([]byte, ENIPHeaderLen, ENIPHeaderLen+len(body))
	binary.LittleEndian.PutUint16(b[0:], cmd)
	binary.LittleEndian.PutUint16(b[2:], length)
	binary.LittleEndian.PutUint32(b[8:], status)
	binary.LittleEndian.PutUint32(b[20:], options)
	return append(b, body...)
}

func TestProbeENIPEncapsulation(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want Result
	}{
		{"empty", nil, Incomplete},
		{"short header", make([]byte, 23), Incomplete},
		{"list identity request", enipHeader(ENIPListIdentity, 0, 0, 0, nil), Recognized},
		{"nop with zero options", enipHeader(ENIPNop, 0, 0, 0, nil), Recognized},
		{"nop with options", enipHeader(ENIPNop, 0, 0, 1, nil), Unrecognized},
		{"register session ok", enipHeader(ENIPRegisterSession, 4, 0, 0, []byte{1, 0, 0, 0}), Recognized},
		{"register session wrong length", enipHeader(ENIPRegisterSession, 5, 0, 0, nil), Unrecognized},
		{"unregister length 0", enipHeader(ENIPUnregisterSession, 0, 0, 0, nil), Recognized},
		{"unregister length 4", enipHeader(ENIPUnregisterSession, 4, 0, 0, nil), Recognized},
		{"unregister length 2", enipHeader(ENIPUnregisterSession, 2, 0, 0, nil), Unrecognized},
		{"unknown command", enipHeader(0x0001, 0, 0, 0, nil), Unrecognized},
		{"unknown status", enipHeader(ENIPListIdentity, 0, 0x1234, 0, nil), Unrecognized},
		{"known error status", enipHeader(ENIPSendRRData, 0, ENIPStatusInvalidSession, 0, nil), Recognized},
		{"list interfaces zero items", enipHeader(ENIPListInterfaces, 2, 0, 0, []byte{0, 0}), Recognized},
		{"list interfaces count too big", enipHeader(ENIPListInterfaces, 2, 0, 0, []byte{3, 0}), Unrecognized},
		{"list interfaces no count", enipHeader(ENIPListInterfaces, 0, 0, 0, nil), Unrecognized},
		// A TCP segment may carry only the start of a long SendRRData message.
		{"length exceeds buffer", enipHeader(ENIPSendRRData, 500, 0, 0, make([]byte, 10)), Recognized},
		// Typical non-ENIP payloads.
		{"ascii http", append([]byte("GET / HTTP/1.1\r\nHost: example\r\n"), 0, 0, 0), Unrecognized},
		{"all 0xff", func() []byte {
			b := make([]byte, 40)
			for i := range b {
				b[i] = 0xff
			}
			return b
		}(), Unrecognized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProbeENIPEncapsulation(tt.in); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegistryDetectENIP(t *testing.T) {
	r := Default()
	good := enipHeader(ENIPListIdentity, 0, 0, 0, nil)
	bad := enipHeader(0x0001, 0, 0, 0, nil)

	find := func(ms []Match, name string) *Match {
		for i := range ms {
			if ms[i].Protocol == name {
				return &ms[i]
			}
		}
		return nil
	}

	t.Run("UDP 44818 discovery (F-01)", func(t *testing.T) {
		m := find(r.Detect(UDP, 50000, 44818, good), "EtherNet/IP")
		if m == nil || m.Result != Recognized || !m.PortHint {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("UDP 2222 implicit I/O keeps matching", func(t *testing.T) {
		m := find(r.Detect(UDP, 2222, 2222, good), "EtherNet/IP")
		if m == nil || !m.PortHint {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("content match on a non-standard port", func(t *testing.T) {
		m := find(r.Detect(TCP, 50000, 50001, good), "EtherNet/IP")
		if m == nil || m.PortHint {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("garbage on the ENIP port is not ENIP", func(t *testing.T) {
		if m := find(r.Detect(TCP, 50000, 44818, bad), "EtherNet/IP"); m != nil {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("empty payload on the port is weak evidence", func(t *testing.T) {
		m := find(r.Detect(TCP, 50000, 44818, nil), "EtherNet/IP")
		if m == nil || m.Result != Incomplete {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("empty payload off the port is nothing", func(t *testing.T) {
		if m := find(r.Detect(TCP, 50000, 50001, nil), "EtherNet/IP"); m != nil {
			t.Fatalf("got %+v", m)
		}
	})
	t.Run("UDP 2222 is not a TCP hint", func(t *testing.T) {
		if m := find(r.Detect(TCP, 50000, 2222, nil), "EtherNet/IP"); m != nil {
			t.Fatalf("got %+v", m)
		}
	})
}

func TestRegistryPortOnlyProtocols(t *testing.T) {
	r := Default()
	// DNP3 has no content probe yet (plan phase 3).
	ms := r.Detect(TCP, 50000, 20000, []byte{1, 2, 3})
	if len(ms) != 1 || ms[0].Protocol != "DNP3" || !ms[0].PortOnly {
		t.Fatalf("got %+v", ms)
	}
	if ms := r.Detect(TCP, 50000, 50001, []byte{1, 2, 3}); len(ms) != 0 {
		t.Fatalf("got %+v", ms)
	}
}

func TestRegistryHintPorts(t *testing.T) {
	got := Default().HintPorts()
	want := map[uint16]string{44818: "EtherNet/IP", 2222: "EtherNet/IP", 4840: "OPC UA", 502: "Modbus", 20000: "DNP3"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, n := range want {
		if got[p] != n {
			t.Fatalf("port %d: got %q want %q", p, got[p], n)
		}
	}
	if _, ok := got[102]; ok {
		t.Fatal("port 102 must not be claimed as S7 (finding F-05)")
	}
}

func TestRegisterReplacesByName(t *testing.T) {
	r := &Registry{}
	r.Register(Protocol{Name: "x", Transports: TCP})
	r.Register(Protocol{Name: "x", Transports: UDP})
	if ps := r.Protocols(); len(ps) != 1 || ps[0].Transports != UDP {
		t.Fatalf("got %+v", ps)
	}
}

// cpf builds a Common Packet Format datagram from (type, data) items.
func cpf(count uint16, items ...[]byte) []byte {
	b := []byte{byte(count), byte(count >> 8)}
	for _, it := range items {
		b = append(b, it...)
	}
	return b
}

func cpfItem(typ uint16, data []byte) []byte {
	b := []byte{byte(typ), byte(typ >> 8), byte(len(data)), byte(len(data) >> 8)}
	return append(b, data...)
}

func TestProbeENIPImplicitIO(t *testing.T) {
	addr := cpfItem(0x8002, make([]byte, 8))
	data := cpfItem(0x00B1, []byte{1, 0, 0xAA, 0xBB})
	// Real capture (minicps testbed, UDP 2222, 20 bytes).
	real20 := []byte{0x02, 0x00, 0x02, 0x80, 0x08, 0x00, 0x05, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb1, 0x00, 0x02, 0x00, 0x01, 0x00}

	tests := []struct {
		name string
		in   []byte
		want Result
	}{
		{"real capture, idle heartbeat", real20, Recognized},
		{"sequenced address plus data", cpf(2, addr, data), Recognized},
		{"connected address plus data", cpf(2, cpfItem(0x00A1, []byte{1, 2, 3, 4}), data), Recognized},
		{"with sockaddr item", cpf(3, addr, data, cpfItem(0x8001, make([]byte, 16))), Recognized},
		{"too short", []byte{2, 0, 2}, Incomplete},
		{"count 1", cpf(1, addr), Unrecognized},
		{"count 9", cpf(9, addr, data), Unrecognized},
		{"first item not an address", cpf(2, data, addr), Unrecognized},
		{"address item wrong length", cpf(2, cpfItem(0x8002, make([]byte, 6)), data), Unrecognized},
		{"no connected data item", cpf(2, addr, cpfItem(0x8000, make([]byte, 16))), Unrecognized},
		{"unknown item type", cpf(2, addr, cpfItem(0x1234, []byte{1})), Unrecognized},
		{"item length runs past datagram", append(cpf(2, addr), 0xB1, 0x00, 0x20, 0x00, 1, 2), Unrecognized},
		{"trailing bytes", append(cpf(2, addr, data), 0xFF), Unrecognized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProbeENIPImplicitIO(tt.in); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestProbeENIPUDP(t *testing.T) {
	if ProbeENIPUDP(nil) != Incomplete {
		t.Fatal("empty must be Incomplete")
	}
	if ProbeENIPUDP(enipHeader(ENIPListIdentity, 0, 0, 0, nil)) != Recognized {
		t.Fatal("encapsulation must be recognised on UDP")
	}
	if ProbeENIPUDP(cpf(2, cpfItem(0x8002, make([]byte, 8)), cpfItem(0x00B1, []byte{1, 0}))) != Recognized {
		t.Fatal("implicit I/O must be recognised on UDP")
	}
	if ProbeENIPUDP([]byte("short garbage")) != Unrecognized {
		t.Fatal("a short datagram cannot become valid later")
	}
	// TCP must not accept implicit I/O: it only exists in UDP datagrams.
	p, _ := Default().Lookup("EtherNet/IP")
	tcpProbe := p.ProbeFor(TCP)
	if tcpProbe(cpf(2, cpfItem(0x8002, make([]byte, 8)), cpfItem(0x00B1, []byte{1, 0}))) == Recognized {
		t.Fatal("implicit I/O must not be recognised on TCP")
	}
}
