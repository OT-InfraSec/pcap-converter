package detect

// S7comm (Siemens) travels in ISO-on-TCP: a TPKT header (RFC 1006), a COTP
// header (ISO 8073) and the S7 PDU. TCP port 102 is shared with other COTP
// users (MMS of IEC 61850, ICCP), so the port is only a hint: a connection is
// S7 when its data TPDUs carry the S7 protocol id 0x32.
const (
	// S7Port is the registered ISO-TSAP port.
	S7Port uint16 = 102
	// S7ProtocolID starts every S7comm PDU.
	S7ProtocolID byte = 0x32
)

// COTP PDU types (high nibble of the type byte; the low nibble is the credit
// for connection PDUs and the TPDU number for data).
const (
	cotpCR byte = 0xe0
	cotpCC byte = 0xd0
	cotpDR byte = 0x80
	cotpDC byte = 0xc0
	cotpDT byte = 0xf0
	cotpER byte = 0x70
)

// S7 ROSCTR (remote operating service control) values.
const (
	s7Job      byte = 1
	s7Ack      byte = 2
	s7AckData  byte = 3
	s7Userdata byte = 7
)

func validROSCTR(r byte) bool { return r == s7Job || r == s7Ack || r == s7AckData || r == s7Userdata }

// ProbeS7 checks a TCP payload for the start of S7comm in ISO-on-TCP.
//
// A connection request or confirmation is valid TPKT and COTP but says nothing
// about the user of the connection, so it is Incomplete: the labeler keeps the
// port hint until a data TPDU decides. A data TPDU is Recognized when it starts
// with the S7 protocol id and a known ROSCTR, and Unrecognized otherwise.
func ProbeS7(b []byte) Result {
	if len(b) == 0 {
		return Incomplete
	}
	if b[0] != 3 {
		return Unrecognized
	}
	if len(b) < 7 {
		return Incomplete
	}
	if tpktLen := int(b[2])<<8 | int(b[3]); tpktLen < 6 {
		return Unrecognized
	}
	li := int(b[4])
	switch b[5] & 0xf0 {
	case cotpCR, cotpCC, cotpDR, cotpDC:
		if li < 6 || 5+li > int(b[2])<<8|int(b[3]) {
			return Unrecognized
		}
		return Incomplete
	case cotpDT:
		if li != 2 {
			return Unrecognized
		}
		if len(b) < 8 {
			return Incomplete
		}
		if b[7] != S7ProtocolID {
			return Unrecognized
		}
		if len(b) < 9 {
			return Incomplete
		}
		if !validROSCTR(b[8]) {
			return Unrecognized
		}
		return Recognized
	}
	return Unrecognized
}
