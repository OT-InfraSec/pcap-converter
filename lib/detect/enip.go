package detect

import "encoding/binary"

// EtherNet/IP encapsulation (ODVA, "EtherNet/IP Adaptation of CIP", chapter 2).
// The header is 24 bytes, all fields little endian:
// command(2) length(2) session(4) status(4) sender context(8) options(4).

// ENIPHeaderLen is the size of the encapsulation header.
const ENIPHeaderLen = 24

// ENIP encapsulation commands.
const (
	ENIPNop               uint16 = 0x0000
	ENIPListServices      uint16 = 0x0004
	ENIPListIdentity      uint16 = 0x0063
	ENIPListInterfaces    uint16 = 0x0064
	ENIPRegisterSession   uint16 = 0x0065
	ENIPUnregisterSession uint16 = 0x0066
	ENIPSendRRData        uint16 = 0x006F
	ENIPSendUnitData      uint16 = 0x0070
	ENIPIndicateStatus    uint16 = 0x0072
	ENIPCancel            uint16 = 0x0073
)

// ENIP encapsulation status codes.
const (
	ENIPStatusSuccess            uint32 = 0x00
	ENIPStatusInvalidCommand     uint32 = 0x01
	ENIPStatusNoResources        uint32 = 0x02
	ENIPStatusIncorrectData      uint32 = 0x03
	ENIPStatusInvalidSession     uint32 = 0x64
	ENIPStatusInvalidLength      uint32 = 0x65
	ENIPStatusUnsupportedProtRev uint32 = 0x69
	ENIPStatusEncapHeaderError   uint32 = 0x6A
)

// Well-known EtherNet/IP ports. TCP 44818 and UDP 44818 carry encapsulation
// commands (ListIdentity is usually UDP/44818 broadcast); UDP 2222 carries
// implicit (class 1) I/O.
const (
	ENIPPortExplicit uint16 = 44818
	ENIPPortImplicit uint16 = 2222
)

func knownENIPCommand(c uint16) bool {
	switch c {
	case ENIPNop, ENIPListServices, ENIPListIdentity, ENIPListInterfaces,
		ENIPRegisterSession, ENIPUnregisterSession, ENIPSendRRData,
		ENIPSendUnitData, ENIPIndicateStatus, ENIPCancel:
		return true
	}
	return false
}

func knownENIPStatus(s uint32) bool {
	switch s {
	case ENIPStatusSuccess, ENIPStatusInvalidCommand, ENIPStatusNoResources,
		ENIPStatusIncorrectData, ENIPStatusInvalidSession, ENIPStatusInvalidLength,
		ENIPStatusUnsupportedProtRev, ENIPStatusEncapHeaderError:
		return true
	}
	return false
}

// ProbeENIPEncapsulation checks for a TCP or UDP encapsulation header.
//
// It requires a known command, a known status and the per-command length
// rules below. These rules follow Suricata's probe (rust/src/enip/enip.rs)
// and are still to be confirmed against the ODVA specification (finding F-02):
//   - Nop: options must be 0.
//   - RegisterSession: length must be 4.
//   - UnregisterSession: length must be 4 or 0.
//   - ListInterfaces: the item count must fit in the payload.
//
// The length field is not required to fit the buffer, because a TCP segment
// may hold only the start of a message. Fewer than 24 bytes is Incomplete.
func ProbeENIPEncapsulation(b []byte) Result {
	if len(b) < ENIPHeaderLen {
		return Incomplete
	}
	cmd := binary.LittleEndian.Uint16(b[0:2])
	length := binary.LittleEndian.Uint16(b[2:4])
	status := binary.LittleEndian.Uint32(b[8:12])
	options := binary.LittleEndian.Uint32(b[20:24])

	if !knownENIPCommand(cmd) || !knownENIPStatus(status) {
		return Unrecognized
	}
	switch cmd {
	case ENIPNop:
		if options != 0 {
			return Unrecognized
		}
	case ENIPRegisterSession:
		if length != 4 {
			return Unrecognized
		}
	case ENIPUnregisterSession:
		if length != 4 && length != 0 {
			return Unrecognized
		}
	case ENIPListInterfaces:
		rest := b[ENIPHeaderLen:]
		if len(rest) < 2 {
			return Unrecognized
		}
		n := int(binary.LittleEndian.Uint16(rest[0:2]))
		if len(rest) < 2+2*n {
			return Unrecognized
		}
	}
	return Recognized
}

// Common Packet Format item types (ODVA, CIP Volume 2, chapter 2-6).
const (
	cpfItemConnectedAddress uint16 = 0x00A1
	cpfItemConnectedData    uint16 = 0x00B1
	cpfItemSockaddrOT       uint16 = 0x8000
	cpfItemSockaddrTO       uint16 = 0x8001
	cpfItemSequencedAddress uint16 = 0x8002
)

// ProbeENIPImplicitIO checks for implicit (class 0/1) I/O, which travels in
// bare UDP datagrams on port 2222 without an encapsulation header:
//
//	item count (u16) | address item | connected data item | [sockaddr items]
//
// The address item is a Sequenced Address Item (0x8002, 8 bytes: connection ID
// and sequence number) or a Connected Address Item (0x00A1, 4 bytes). Each item
// is type (u16), length (u16), data. All fields are little endian. Items must
// fill the datagram exactly. Suricata does not recognise this traffic.
func ProbeENIPImplicitIO(b []byte) Result {
	if len(b) < 6 {
		return Incomplete
	}
	count := int(binary.LittleEndian.Uint16(b[0:2]))
	if count < 2 || count > 4 {
		return Unrecognized
	}
	off := 2
	sawData := false
	for i := 0; i < count; i++ {
		if len(b)-off < 4 {
			return Unrecognized
		}
		typ := binary.LittleEndian.Uint16(b[off:])
		n := int(binary.LittleEndian.Uint16(b[off+2:]))
		off += 4
		if len(b)-off < n {
			return Unrecognized
		}
		switch {
		case i == 0 && typ == cpfItemSequencedAddress && n == 8:
		case i == 0 && typ == cpfItemConnectedAddress && n == 4:
		case i == 0:
			return Unrecognized
		case typ == cpfItemConnectedData:
			sawData = true
		case (typ == cpfItemSockaddrOT || typ == cpfItemSockaddrTO) && n == 16:
		default:
			return Unrecognized
		}
		off += n
	}
	if off != len(b) || !sawData {
		return Unrecognized
	}
	return Recognized
}

// ProbeENIPUDP accepts either an encapsulation message or implicit I/O. A UDP
// datagram is complete, so a short one cannot become valid later: only an empty
// payload is Incomplete.
func ProbeENIPUDP(b []byte) Result {
	if len(b) == 0 {
		return Incomplete
	}
	if ProbeENIPEncapsulation(b) == Recognized || ProbeENIPImplicitIO(b) == Recognized {
		return Recognized
	}
	return Unrecognized
}
