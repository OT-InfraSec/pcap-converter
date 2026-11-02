package detect

import "encoding/binary"

// Modbus/TCP (MODBUS Messaging on TCP/IP Implementation Guide V1.0b, 3.1.3).
//
// An ADU is the 7-byte MBAP header followed by the PDU:
//
//	transaction id (2) | protocol id (2, always 0) | length (2) | unit id (1) |
//	function code (1) | data (0..252)
//
// length counts the unit id and the PDU, so it is 2..254 and a whole ADU is at
// most 260 bytes.

const (
	// ModbusMBAPLen is the size of the MBAP header.
	ModbusMBAPLen = 7
	// ModbusMaxADULen is the largest legal ADU (7 + 253).
	ModbusMaxADULen = 260
	// ModbusPort is the registered TCP port.
	ModbusPort uint16 = 502
)

// ModbusADUSize returns the total size of the ADU that starts at b, and whether
// b starts with a plausible MBAP header followed by a valid function code.
// The size can exceed len(b) when only part of the ADU is present.
func ModbusADUSize(b []byte) (size int, ok bool) {
	if len(b) < ModbusMBAPLen+1 {
		return 0, false
	}
	if binary.BigEndian.Uint16(b[2:4]) != 0 {
		return 0, false
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < 2 || length > 254 {
		return 0, false
	}
	fc := b[7]
	// 0 is reserved. Exception responses set the top bit on a valid code.
	if fc == 0 || fc == 0x80 {
		return 0, false
	}
	return 6 + length, true
}

// ProbeModbusTCP checks that a TCP payload starts with a Modbus ADU.
//
// Fewer than 8 bytes cannot be judged and are Incomplete. The probe looks at
// the first ADU only: the following bytes may be a further ADU (pipelining) or,
// until TCP reassembly exists, the continuation of a long one. Suricata's probe
// comes from the sawp-modbus crate, which is not in its tree; the exact limits
// there are still to be compared (finding F-04).
func ProbeModbusTCP(b []byte) Result {
	if len(b) < ModbusMBAPLen+1 {
		return Incomplete
	}
	if _, ok := ModbusADUSize(b); ok {
		return Recognized
	}
	return Unrecognized
}

// SplitModbusADUs cuts a TCP payload into complete ADUs. rest holds the bytes
// of a trailing partial ADU, or of anything that does not parse as one. A
// payload that does not start with a valid ADU yields no ADUs.
func SplitModbusADUs(b []byte) (adus [][]byte, rest []byte) {
	for len(b) > 0 {
		size, ok := ModbusADUSize(b)
		if !ok || size > len(b) {
			return adus, b
		}
		adus = append(adus, b[:size])
		b = b[size:]
	}
	return adus, nil
}
