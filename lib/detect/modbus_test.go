package detect

import (
	"bytes"
	"testing"
)

// adu builds a Modbus/TCP ADU: MBAP header plus unit id, function code, data.
func adu(txn uint16, proto uint16, unit, fc byte, data []byte) []byte {
	length := 2 + len(data)
	b := []byte{byte(txn >> 8), byte(txn), byte(proto >> 8), byte(proto), byte(length >> 8), byte(length), unit, fc}
	return append(b, data...)
}

func TestProbeModbusTCP(t *testing.T) {
	// Real captures (minicps testbed, TCP 502).
	readRequest := []byte{0x2d, 0xe9, 0x00, 0x00, 0x00, 0x06, 0x03, 0x03, 0x37, 0xd0, 0x00, 0x04} // FC3, 12 bytes
	rwRequest := []byte{0xc1, 0xba, 0x00, 0x00, 0x00, 0x33, 0x01, 0x17, 0x39, 0xd8, 0x00, 0x0a}   // FC23 header only

	tests := []struct {
		name string
		in   []byte
		want Result
	}{
		{"empty", nil, Incomplete},
		{"7 bytes", make([]byte, 7), Incomplete},
		{"real read holding registers request", readRequest, Recognized},
		{"real read/write request, first segment only", rwRequest, Recognized},
		{"read coils request", adu(1, 0, 1, 0x01, []byte{0, 0, 0, 8}), Recognized},
		{"exception response", adu(1, 0, 1, 0x83, []byte{0x02}), Recognized},
		{"maximum PDU", adu(1, 0, 1, 0x10, make([]byte, 252)), Recognized},
		{"protocol id not zero", adu(1, 1, 1, 0x03, []byte{0, 0, 0, 1}), Unrecognized},
		{"function code 0", adu(1, 0, 1, 0x00, nil), Unrecognized},
		{"function code 0x80", adu(1, 0, 1, 0x80, nil), Unrecognized},
		{"length 1 (no function code)", []byte{0, 1, 0, 0, 0, 1, 1, 3}, Unrecognized},
		{"length 0", []byte{0, 1, 0, 0, 0, 0, 1, 3}, Unrecognized},
		{"length 255", []byte{0, 1, 0, 0, 0, 255, 1, 3}, Unrecognized},
		{"http", []byte("GET / HTTP/1.1\r\nHost: x\r\n"), Unrecognized},
		{"tls client hello start", []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc}, Unrecognized},
		{"enip list identity", enipHeader(ENIPListIdentity, 0, 0, 0, nil), Unrecognized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProbeModbusTCP(tt.in); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestModbusADUSize(t *testing.T) {
	if n, ok := ModbusADUSize(adu(1, 0, 1, 0x03, []byte{0, 0, 0, 1})); !ok || n != 12 {
		t.Fatalf("got %d %v", n, ok)
	}
	if n, ok := ModbusADUSize(adu(1, 0, 1, 0x10, make([]byte, 252))); !ok || n != ModbusMaxADULen {
		t.Fatalf("max ADU: got %d %v, want %d", n, ok, ModbusMaxADULen)
	}
}

func TestSplitModbusADUs(t *testing.T) {
	a := adu(1, 0, 1, 0x03, []byte{0, 0, 0, 1})
	b := adu(2, 0, 1, 0x06, []byte{0, 5, 0, 9})

	tests := []struct {
		name     string
		in       []byte
		wantADUs int
		wantRest int
	}{
		{"empty", nil, 0, 0},
		{"one", a, 1, 0},
		{"two pipelined", append(append([]byte{}, a...), b...), 2, 0},
		{"one and a partial tail", append(append([]byte{}, a...), b[:5]...), 1, 5},
		{"only a partial ADU", a[:9], 0, 9},
		{"garbage", []byte("hello world, this is not modbus"), 0, 31},
		{"valid then garbage", append(append([]byte{}, a...), []byte("junk junk junk")...), 1, 14},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adus, rest := SplitModbusADUs(tt.in)
			if len(adus) != tt.wantADUs || len(rest) != tt.wantRest {
				t.Fatalf("got %d ADUs, %d rest bytes; want %d, %d", len(adus), len(rest), tt.wantADUs, tt.wantRest)
			}
			var joined []byte
			for _, x := range adus {
				joined = append(joined, x...)
			}
			if !bytes.Equal(append(joined, rest...), tt.in) && len(tt.in) > 0 {
				t.Fatal("ADUs plus rest must reassemble the input")
			}
		})
	}
}

func TestRegistryDetectModbus(t *testing.T) {
	r := Default()
	good := adu(7, 0, 1, 0x03, []byte{0, 0, 0, 2})
	find := func(ms []Match) *Match {
		for i := range ms {
			if ms[i].Protocol == "Modbus" {
				return &ms[i]
			}
		}
		return nil
	}
	if m := find(r.Detect(TCP, 50000, 502, good)); m == nil || m.Result != Recognized || !m.PortHint || m.PortOnly {
		t.Fatalf("modbus on 502: %+v", m)
	}
	if m := find(r.Detect(TCP, 50000, 50001, good)); m == nil || m.PortHint {
		t.Fatalf("modbus content on another port: %+v", m)
	}
	if m := find(r.Detect(TCP, 50000, 502, []byte("GET / HTTP/1.1\r\n"))); m != nil {
		t.Fatalf("http on 502 must not be Modbus: %+v", m)
	}
	if m := find(r.Detect(TCP, 50000, 502, nil)); m == nil || m.Result != Incomplete {
		t.Fatalf("empty payload on 502: %+v", m)
	}
	if m := find(r.Detect(UDP, 50000, 502, good)); m != nil {
		t.Fatalf("Modbus/TCP must not match UDP: %+v", m)
	}
}

func FuzzModbus(f *testing.F) {
	f.Add([]byte{})
	f.Add(adu(1, 0, 1, 0x03, []byte{0, 0, 0, 1}))
	f.Add(append(adu(1, 0, 1, 0x03, nil), adu(2, 0, 1, 0x04, nil)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = ProbeModbusTCP(b)
		adus, rest := SplitModbusADUs(b)
		total := len(rest)
		for _, a := range adus {
			total += len(a)
			if len(a) < ModbusMBAPLen+1 || len(a) > ModbusMaxADULen {
				t.Fatalf("ADU size %d out of range", len(a))
			}
		}
		if total != len(b) {
			t.Fatalf("split lost bytes: %d of %d", total, len(b))
		}
	})
}
