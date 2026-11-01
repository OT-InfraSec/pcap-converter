package detect

import (
	"reflect"
	"testing"
)

func TestDecodeModbusADU(t *testing.T) {
	tests := []struct {
		name       string
		in         []byte
		fc         byte
		fcName     string
		exception  bool
		excCode    byte
		access     ModbusAccess
		addr, qty  int // -1 = not present
		events     []string
		unit       byte
		txn        uint16
		wantOK     bool
		wantDetail string
	}{
		{name: "read holding registers (real capture)", in: []byte{0x2d, 0xe9, 0, 0, 0, 6, 3, 3, 0x37, 0xd0, 0, 4},
			fc: 3, fcName: "Read Holding Registers", access: ModbusRead, addr: 0x37d0, qty: 4, unit: 3, txn: 0x2de9, wantOK: true},
		{name: "write single coil", in: adu(1, 0, 1, 5, []byte{0, 10, 0xff, 0}),
			fc: 5, fcName: "Write Single Coil", access: ModbusWrite, addr: 10, qty: 1, unit: 1, txn: 1, wantOK: true},
		{name: "write multiple registers", in: adu(1, 0, 1, 16, []byte{0, 1, 0, 2, 4, 0, 1, 0, 2}),
			fc: 16, fcName: "Write Multiple Registers", access: ModbusWrite, addr: 1, qty: 2, unit: 1, txn: 1, wantOK: true},
		{name: "read/write multiple registers reports the read range", in: adu(1, 0, 1, 23, []byte{0x39, 0xd8, 0, 10, 0x39, 0xe0, 0, 2, 4, 0, 1, 0, 2}),
			fc: 23, fcName: "Read/Write Multiple Registers", access: ModbusReadWrite, addr: 0x39d8, qty: 10, unit: 1, txn: 1, wantOK: true},
		{name: "diagnostics", in: adu(1, 0, 1, 8, []byte{0, 1, 0, 0}),
			fc: 8, fcName: "Diagnostics", access: ModbusDiagnostic, addr: -1, qty: -1, unit: 1, txn: 1, wantOK: true},
		{name: "exception response", in: adu(1, 0, 1, 0x83, []byte{0x02}),
			fc: 3, fcName: "Read Holding Registers", exception: true, excCode: 2, access: ModbusRead, addr: -1, qty: -1, unit: 1, txn: 1, wantOK: true},
		{name: "exception with unknown code", in: adu(1, 0, 1, 0x83, []byte{0x42}),
			fc: 3, fcName: "Read Holding Registers", exception: true, excCode: 0x42, access: ModbusRead, addr: -1, qty: -1, unit: 1, txn: 1, wantOK: true,
			events: []string{ModbusEventInvalidException}},
		{name: "exception on a high function code", in: adu(1, 0, 1, 0xe5, []byte{0x01}),
			fc: 0x65, fcName: "User Defined", exception: true, excCode: 1, access: ModbusUnknown, addr: -1, qty: -1, unit: 1, txn: 1, wantOK: true},
		{name: "unassigned function code", in: adu(1, 0, 1, 0x50, []byte{1}),
			fc: 0x50, fcName: "Unknown", access: ModbusUnknown, addr: -1, qty: -1, unit: 1, txn: 1, wantOK: true,
			events: []string{ModbusEventUnknownFunction}},
		{name: "user defined function code is not an anomaly", in: adu(1, 0, 1, 0x41, []byte{1}),
			fc: 0x41, fcName: "User Defined", access: ModbusUnknown, addr: -1, qty: -1, unit: 1, txn: 1, wantOK: true},
		{name: "non-zero protocol id", in: adu(1, 1, 1, 3, []byte{0, 0, 0, 1}), wantOK: false},
		{name: "short", in: []byte{0, 1, 0, 0, 0, 2, 1}, wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := DecodeModbusADU(tc.in, true)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if m.FunctionCode != tc.fc || m.FunctionName != tc.fcName || m.IsException != tc.exception ||
				m.ExceptionCode != tc.excCode || m.Access != tc.access || m.UnitID != tc.unit || m.TransactionID != tc.txn {
				t.Errorf("got %+v", m)
			}
			if m.Address != tc.addr || m.Quantity != tc.qty {
				t.Errorf("addr/qty = %d/%d, want %d/%d", m.Address, m.Quantity, tc.addr, tc.qty)
			}
			if !reflect.DeepEqual(m.Events, tc.events) {
				t.Errorf("events = %v, want %v", m.Events, tc.events)
			}
		})
	}
}

func TestDecodeModbusADUExceptionNames(t *testing.T) {
	m, _ := DecodeModbusADU(adu(1, 0, 1, 0x83, []byte{0x02}), false)
	if m.ExceptionName != "Illegal Data Address" {
		t.Errorf("exception name = %q", m.ExceptionName)
	}
}

func TestDecodeModbusADURequestShapeEvents(t *testing.T) {
	// A read request must carry 4 data bytes (address, quantity).
	m, ok := DecodeModbusADU(adu(1, 0, 1, 3, []byte{0, 1}), true)
	if !ok {
		t.Fatal("not decoded")
	}
	if m.Address != -1 || m.Quantity != -1 {
		t.Errorf("addr/qty must be absent for a short body: %+v", m)
	}
}

func FuzzDecodeModbusADU(f *testing.F) {
	f.Add([]byte{0x2d, 0xe9, 0, 0, 0, 6, 3, 3, 0x37, 0xd0, 0, 4})
	f.Add(adu(1, 0, 1, 0x83, []byte{2}))
	f.Fuzz(func(t *testing.T, b []byte) { DecodeModbusADU(b, true); DecodeModbusADU(b, false) })
}

func TestDecodeModbusADUReadWriteWriteRange(t *testing.T) {
	m, _ := DecodeModbusADU(adu(1, 0, 1, 23, []byte{0x39, 0xd8, 0, 10, 0x39, 0xe0, 0, 2, 4, 0, 1, 0, 2}), true)
	if m.WriteAddress != 0x39e0 || m.WriteQuantity != 2 {
		t.Errorf("write range = %d/%d", m.WriteAddress, m.WriteQuantity)
	}
}
