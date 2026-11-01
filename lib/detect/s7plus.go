package detect

import "encoding/binary"

// S7CommPlus (Siemens S7-1200 firmware 4 and later, S7-1500) uses the same
// TPKT and COTP framing as S7comm on port 102 but starts its PDU with the
// protocol id 0x72 and a version byte.
//
// Layout of the PDU, as the open-source Wireshark S7CommPlus dissector and
// Snap7-era reverse engineering describe it. It has NOT been checked against
// real traffic or a reference dissector (tshark ships none): treat the field
// names as provisional and keep the raw numbers.
//
//	0x72 | version | data length (2) | data | 0x72 | version | 0x00 0x00
//
// and the data of a request or response:
//
//	opcode | reserved (2) | function (2) | reserved (2) | sequence (2) | session id (4) | transport flags
const (
	// S7PlusProtocolID starts every S7CommPlus PDU.
	S7PlusProtocolID byte = 0x72

	s7PlusOpRequest      byte = 0x31
	s7PlusOpResponse     byte = 0x32
	s7PlusOpNotification byte = 0x33
	s7PlusHeaderLen           = 4
	s7PlusTrailerLen          = 4
	s7PlusMinData             = 15 // opcode .. transport flags
)

// Events of the S7CommPlus decoder.
const S7PlusEventInvalid = "invalid_s7plus" // header, length or trailer inconsistent

func validS7PlusVersion(v byte) bool { return v >= 1 && v <= 3 }

// ProbeS7Plus checks a TCP payload for an S7CommPlus data TPDU in ISO-on-TCP.
// Connection requests and confirmations are Incomplete (they say nothing about
// the user of the connection), as in ProbeS7.
func ProbeS7Plus(b []byte) Result {
	if len(b) == 0 {
		return Incomplete
	}
	if b[0] != 3 {
		return Unrecognized
	}
	if len(b) < 7 {
		return Incomplete
	}
	tpktLen := int(b[2])<<8 | int(b[3])
	if tpktLen < 6 {
		return Unrecognized
	}
	li := int(b[4])
	switch b[5] & 0xf0 {
	case cotpCR, cotpCC, cotpDR, cotpDC:
		if li < 6 || 5+li > tpktLen {
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
		if b[7] != S7PlusProtocolID {
			return Unrecognized
		}
		if len(b) < 9 {
			return Incomplete
		}
		if !validS7PlusVersion(b[8]) {
			return Unrecognized
		}
		return Recognized
	}
	return Unrecognized
}

// S7PlusHeader is the decoded start of an S7CommPlus PDU.
type S7PlusHeader struct {
	Version       byte
	DataLength    uint16
	Opcode        byte
	OpcodeName    string
	Function      uint16 // request and response only
	FunctionName  string
	Sequence      uint16
	SessionID     uint32
	TransportFlag byte
	HasFields     bool // Function, Sequence, SessionID were decoded (request or response)
	TrailerOK     bool
}

var s7PlusFunctions = map[uint16]string{
	0x04b1: "Error",
	0x04bb: "Explore",
	0x04ca: "CreateObject",
	0x04d4: "DeleteObject",
	0x04f2: "SetVariable",
	0x0524: "GetLink",
	0x0542: "SetMultiVariables",
	0x054c: "GetMultiVariables",
	0x0556: "BeginSequence",
	0x0560: "EndSequence",
	0x056b: "Invoke",
}

func s7PlusOpcodeName(op byte) string {
	switch op {
	case s7PlusOpRequest:
		return "Request"
	case s7PlusOpResponse:
		return "Response"
	case s7PlusOpNotification:
		return "Notification"
	}
	return "Unknown"
}

// decodeS7PlusPDU decodes the header of one reassembled PDU (starting at the
// protocol id). It returns false when the PDU is cut short or its length field
// and trailer do not fit the frame.
func decodeS7PlusPDU(m *S7Message, b []byte) bool {
	if len(b) < s7PlusHeaderLen || !validS7PlusVersion(b[1]) {
		return false
	}
	h := &S7PlusHeader{Version: b[1], DataLength: binary.BigEndian.Uint16(b[2:4])}
	m.Plus = h
	data := b[s7PlusHeaderLen:]
	if int(h.DataLength) > len(data) {
		return false
	}
	rest := data[h.DataLength:]
	h.TrailerOK = len(rest) >= s7PlusTrailerLen && rest[0] == S7PlusProtocolID && rest[1] == h.Version
	data = data[:h.DataLength]
	if len(data) == 0 {
		return h.TrailerOK
	}
	h.Opcode = data[0]
	h.OpcodeName = s7PlusOpcodeName(h.Opcode)
	if (h.Opcode == s7PlusOpRequest || h.Opcode == s7PlusOpResponse) && len(data) >= s7PlusMinData {
		h.HasFields = true
		h.Function = binary.BigEndian.Uint16(data[3:5])
		h.FunctionName = s7PlusFunctions[h.Function]
		h.Sequence = binary.BigEndian.Uint16(data[7:9])
		h.SessionID = binary.BigEndian.Uint32(data[9:13])
		h.TransportFlag = data[13]
	}
	return h.TrailerOK
}
