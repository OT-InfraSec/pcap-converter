package detect

import (
	"reflect"
	"testing"
)

func u16(v ...uint16) []byte {
	var b []byte
	for _, x := range v {
		b = append(b, byte(x>>8), byte(x))
	}
	return b
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// Rules mirror sawp-modbus (the parser inside Suricata), so the event names
// can be compared with Suricata's: invalid_length, invalid_value.
func TestDecodeModbusADUValidation(t *testing.T) {
	L, V := ModbusEventInvalidLength, ModbusEventInvalidValue
	tests := []struct {
		name    string
		in      []byte
		request bool
		want    []string
	}{
		// Reads.
		{"read holding ok", adu(1, 0, 1, 3, u16(0, 125)), true, nil},
		{"read holding qty 0", adu(1, 0, 1, 3, u16(0, 0)), true, []string{V}},
		{"read holding qty 126", adu(1, 0, 1, 3, u16(0, 126)), true, []string{V}},
		{"read coils qty 2000", adu(1, 0, 1, 1, u16(0, 2000)), true, nil},
		{"read coils qty 2001", adu(1, 0, 1, 1, u16(0, 2001)), true, []string{V}},
		{"read with extra bytes", adu(1, 0, 1, 3, cat(u16(0, 4), u16(0xffff))), true, []string{L}},
		{"read with 2 bytes", adu(1, 0, 1, 3, u16(0)), true, []string{L}},
		{"read with no body", adu(1, 0, 1, 3, nil), true, []string{L}},
		{"read qty 0 and extra bytes", adu(1, 0, 1, 3, cat(u16(0, 0), u16(1))), true, []string{L, V}},
		// Single writes.
		{"coil on", adu(1, 0, 1, 5, u16(5, 0xff00)), true, nil},
		{"coil off", adu(1, 0, 1, 5, u16(5, 0)), true, nil},
		{"coil bad value", adu(1, 0, 1, 5, u16(5, 0x1234)), true, []string{V}},
		{"register any value", adu(1, 0, 1, 6, u16(5, 0x1234)), true, nil},
		{"single write short", adu(1, 0, 1, 6, u16(5)), true, []string{L}},
		// Multiple writes.
		{"write regs ok", adu(1, 0, 1, 16, cat(u16(1, 2), []byte{4}, u16(1, 2))), true, nil},
		// 123 registers is the largest ADU that fits the 253-byte PDU limit.
		{"write regs 123", adu(1, 0, 1, 16, cat(u16(0, 123), []byte{246}, make([]byte, 246))), true, nil},
		{"write regs qty 126 with matching small count", adu(1, 0, 1, 16, cat(u16(0, 126), []byte{4}, make([]byte, 4))), true, []string{V}},
		{"write regs count 6 for qty 2", adu(1, 0, 1, 16, cat(u16(1, 2), []byte{6}, make([]byte, 6))), true, []string{V}},
		{"write regs data shorter than count", adu(1, 0, 1, 16, cat(u16(1, 2), []byte{4}, u16(1))), true, []string{L}},
		{"write regs qty 0", adu(1, 0, 1, 16, cat(u16(1, 0), []byte{0})), true, []string{L}},
		{"write coils ok", adu(1, 0, 1, 15, cat(u16(0, 10), []byte{2, 0xcd, 0x01})), true, nil},
		{"write coils count 1 for qty 10", adu(1, 0, 1, 15, cat(u16(0, 10), []byte{1, 0xcd})), true, []string{V}},
		{"write regs header short", adu(1, 0, 1, 16, u16(1, 2)), true, []string{L}},
		// Mask write, read/write.
		{"mask write ok", adu(1, 0, 1, 22, u16(4, 0xf2, 0x25)), true, nil},
		{"mask write short", adu(1, 0, 1, 22, u16(4, 0xf2)), true, []string{L}},
		{"mask write long", adu(1, 0, 1, 22, u16(4, 0xf2, 0x25, 1)), true, []string{L}},
		{"read/write ok", adu(1, 0, 1, 23, cat(u16(0, 10, 0, 2), []byte{4}, u16(1, 2))), true, nil},
		{"read/write read qty 126", adu(1, 0, 1, 23, cat(u16(0, 126, 0, 2), []byte{4}, u16(1, 2))), true, []string{V}},
		{"read/write count mismatch", adu(1, 0, 1, 23, cat(u16(0, 10, 0, 2), []byte{6}, u16(1, 2))), true, []string{L, V}},
		// Functions without addresses.
		{"exception status ok", adu(1, 0, 1, 7, nil), true, nil},
		{"exception status with data", adu(1, 0, 1, 7, []byte{1}), true, []string{L}},
		{"comm event counter with data", adu(1, 0, 1, 11, []byte{1}), true, []string{L}},
		{"comm event log with data", adu(1, 0, 1, 12, []byte{1}), true, []string{L}},
		{"server id with data", adu(1, 0, 1, 17, []byte{1}), true, []string{L}},
		{"fifo ok", adu(1, 0, 1, 24, u16(0x04de)), true, nil},
		{"fifo 4 bytes", adu(1, 0, 1, 24, u16(1, 2)), true, []string{L}},
		{"read file record empty", adu(1, 0, 1, 20, nil), true, []string{L}},
		{"write file record empty", adu(1, 0, 1, 21, nil), true, []string{L}},
		{"read file record with body", adu(1, 0, 1, 20, []byte{7, 6, 0, 4, 0, 1, 0, 2}), true, nil},
		{"mei without type", adu(1, 0, 1, 43, nil), true, []string{L}},
		{"mei ok", adu(1, 0, 1, 43, []byte{0x0e, 1, 0}), true, nil},
		// Diagnostics.
		{"diag echo", adu(1, 0, 1, 8, cat(u16(0), []byte{0xa5, 0x37})), true, nil},
		{"diag 6 bytes", adu(1, 0, 1, 8, cat(u16(0), []byte{1, 2, 3, 4})), true, []string{L}},
		{"diag restart ok", adu(1, 0, 1, 8, cat(u16(1), []byte{0xff, 0})), true, nil},
		{"diag restart bad", adu(1, 0, 1, 8, cat(u16(1), []byte{0x12, 0x34})), true, []string{V}},
		{"diag counters need zero", adu(1, 0, 1, 8, cat(u16(0x0a), []byte{0, 1})), true, []string{V}},
		{"diag counters zero ok", adu(1, 0, 1, 8, cat(u16(0x0a), []byte{0, 0})), true, nil},
		{"diag delimiter ok", adu(1, 0, 1, 8, cat(u16(3), []byte{0x0a, 0})), true, nil},
		{"diag delimiter bad", adu(1, 0, 1, 8, cat(u16(3), []byte{0x0a, 1})), true, []string{V}},
		{"diag listen only any data", adu(1, 0, 1, 8, cat(u16(4), []byte{1, 2})), true, nil},
		{"diag reserved sub any data", adu(1, 0, 1, 8, cat(u16(0x30), []byte{1, 2})), true, nil},
		// Responses.
		{"read response ok", adu(1, 0, 1, 3, cat([]byte{8}, make([]byte, 8))), false, nil},
		{"read response count mismatch", adu(1, 0, 1, 3, cat([]byte{8}, make([]byte, 6))), false, []string{V}},
		{"read response count 0", adu(1, 0, 1, 3, []byte{0}), false, []string{V}},
		{"read response count 251", adu(1, 0, 1, 3, cat([]byte{251}, make([]byte, 251))), false, []string{V}},
		{"read response empty", adu(1, 0, 1, 3, nil), false, []string{L}},
		{"exception status response 2 bytes", adu(1, 0, 1, 7, []byte{1, 2}), false, []string{L}},
		{"comm event counter response 2 bytes", adu(1, 0, 1, 11, []byte{1, 2}), false, []string{L}},
		{"single write response ok", adu(1, 0, 1, 6, u16(5, 7)), false, nil},
		{"single write response short", adu(1, 0, 1, 6, u16(5)), false, []string{L}},
		{"write multiple response ok", adu(1, 0, 1, 16, u16(1, 2)), false, nil},
		{"write multiple response qty 0", adu(1, 0, 1, 16, u16(1, 0)), false, []string{V}},
		{"write multiple response long", adu(1, 0, 1, 16, u16(1, 2, 3)), false, []string{L}},
		{"mask write response ok", adu(1, 0, 1, 22, u16(4, 0xf2, 0x25)), false, nil},
		// A body is not validated as a request when it is a response.
		{"response not read as request", adu(1, 0, 1, 3, cat([]byte{8}, make([]byte, 8))), false, nil},
		// Exceptions and unknown functions carry no body rules.
		{"exception", adu(1, 0, 1, 0x83, []byte{2}), false, nil},
		{"user defined any body", adu(1, 0, 1, 0x41, []byte{1, 2, 3}), true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := DecodeModbusADU(tc.in, tc.request)
			if !ok {
				t.Fatal("not decoded")
			}
			if !reflect.DeepEqual(m.Events, tc.want) {
				t.Errorf("events = %v, want %v", m.Events, tc.want)
			}
		})
	}
}
