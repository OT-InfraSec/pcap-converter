package hostid

import (
	"encoding/binary"
	"fmt"
	"time"
)

// NetBIOS session service framing (RFC 1002 4.3.1) and the SMB negotiation.
// SMB over TCP 445 uses the same 4-byte frame header with type 0; TCP 139 also
// carries the session request, positive and negative responses and keep-alives.

// Session service packet types.
const (
	NBSSMessage          = 0x00
	NBSSRequest          = 0x81
	NBSSPositiveResponse = 0x82
	NBSSNegativeResponse = 0x83
	NBSSRetarget         = 0x84
	NBSSKeepAlive        = 0x85
)

// NBSSHeader is the 4-byte session service header: a type and a length. The
// length has 17 bits in RFC 1002 (flag bit 0 is the 17th); SMB over TCP uses
// all 24 bits.
type NBSSHeader struct {
	Type   byte
	Length int
}

// ParseNBSS reads the session service header. ok is false when the type is not
// one of the defined ones or the reserved flag bits are set on a non-message
// frame, so arbitrary data on the port is rejected.
func ParseNBSS(b []byte) (NBSSHeader, bool) {
	if len(b) < 4 {
		return NBSSHeader{}, false
	}
	h := NBSSHeader{Type: b[0], Length: int(b[1])<<16 | int(b[2])<<8 | int(b[3])}
	switch h.Type {
	case NBSSMessage:
		return h, true
	case NBSSRequest, NBSSPositiveResponse, NBSSNegativeResponse, NBSSRetarget, NBSSKeepAlive:
		return h, b[1]&0xfe == 0 // 17-bit length: flags other than the extension bit are zero
	}
	return h, false
}

// SMB protocol ids (the first four bytes after the session header).
var (
	smb1ID  = []byte{0xff, 'S', 'M', 'B'}
	smb2ID  = []byte{0xfe, 'S', 'M', 'B'}
	smb3Enc = []byte{0xfd, 'S', 'M', 'B'} // transform header: the message is encrypted
)

// SMBKind classifies the bytes after a session header.
type SMBKind int

const (
	SMBNone SMBKind = iota
	SMB1
	SMB2 // SMB 2.x and 3.x share the header
	SMBEncrypted
)

// ClassifySMB says which SMB generation b starts with.
func ClassifySMB(b []byte) SMBKind {
	if len(b) < 4 {
		return SMBNone
	}
	switch {
	case string(b[:4]) == string(smb1ID):
		return SMB1
	case string(b[:4]) == string(smb2ID):
		return SMB2
	case string(b[:4]) == string(smb3Enc):
		return SMBEncrypted
	}
	return SMBNone
}

// SessionRequest is the body of a session request (RFC 1002 4.3.2): the name
// the client calls and its own name. The calling name is the client's NetBIOS
// computer name.
type SessionRequest struct {
	Called, Calling NBName
}

// DecodeSessionRequest decodes the body of a type 0x81 frame.
func DecodeSessionRequest(body []byte) (SessionRequest, bool) {
	var r SessionRequest
	called, n, ok := decodeNBName(body, 0)
	if !ok {
		return r, false
	}
	calling, _, ok := decodeNBName(body, n)
	if !ok {
		return r, false
	}
	r.Called, r.Calling = called, calling
	return r, true
}

// SMBInfo is what one SMB message says about the peers.
type SMBInfo struct {
	Kind     SMBKind
	Command  uint16 // SMB2 command, or the SMB1 command byte
	Response bool

	// SMB2 NEGOTIATE.
	Dialect         string   // response: the chosen dialect
	OfferedDialects []string // request: the client's list
	SigningEnabled  bool
	SigningRequired bool
	GUID            string // server GUID in a response, client GUID in a request
	SystemTime      time.Time
	ServerStartTime time.Time

	// NTLM is the first CHALLENGE or AUTHENTICATE message in the PDU (session
	// setup), nil if there is none.
	NTLM *NTLMMessage
}

const (
	smb2HeaderLen = 64
	smb2CmdNeg    = 0
	smb2CmdSetup  = 1

	maxDialects = 16
)

// DecodeSMB decodes one SMB message (the bytes after the session header). It
// reads the first message of a compound; later ones are not looked at.
func DecodeSMB(b []byte) (SMBInfo, bool) {
	info := SMBInfo{Kind: ClassifySMB(b)}
	switch info.Kind {
	case SMB1:
		if len(b) < 32 {
			return info, false
		}
		info.Command = uint16(b[4])
		info.Response = b[9]&0x80 != 0 // flags: reply bit
		info.NTLM = findNTLM(b)
		return info, true
	case SMBEncrypted:
		return info, len(b) >= 52 // transform header size; the payload is opaque
	case SMB2:
		if len(b) < smb2HeaderLen || binary.LittleEndian.Uint16(b[4:6]) != smb2HeaderLen {
			return info, false
		}
		info.Command = binary.LittleEndian.Uint16(b[12:14])
		info.Response = binary.LittleEndian.Uint32(b[16:20])&0x1 != 0 // SMB2_FLAGS_SERVER_TO_REDIR
		body := b[smb2HeaderLen:]
		switch {
		case info.Command == smb2CmdNeg && info.Response:
			decodeNegotiateResponse(body, &info)
		case info.Command == smb2CmdNeg:
			decodeNegotiateRequest(body, &info)
		case info.Command == smb2CmdSetup:
			info.NTLM = findNTLM(body)
		}
		return info, true
	}
	return info, false
}

// findNTLM returns the first decodable NTLM CHALLENGE or AUTHENTICATE message.
func findNTLM(b []byte) *NTLMMessage {
	for from := 0; from < len(b); {
		i := FindNTLMSSP(b[from:])
		if i < 0 {
			return nil
		}
		if m, ok := DecodeNTLMSSP(b[from+i:]); ok {
			return &m
		}
		from += i + len(ntlmSignature)
	}
	return nil
}

// decodeNegotiateResponse reads MS-SMB2 2.2.4: StructureSize 65, SecurityMode,
// DialectRevision, NegotiateContextCount, ServerGuid, Capabilities, three
// sizes, SystemTime, ServerStartTime.
func decodeNegotiateResponse(b []byte, info *SMBInfo) {
	if len(b) < 64 || binary.LittleEndian.Uint16(b[0:2]) != 65 {
		return
	}
	info.setSigning(binary.LittleEndian.Uint16(b[2:4]))
	info.Dialect = dialectName(binary.LittleEndian.Uint16(b[4:6]))
	info.GUID = guidString(b[8:24])
	info.SystemTime = fileTime(binary.LittleEndian.Uint64(b[40:48]))
	info.ServerStartTime = fileTime(binary.LittleEndian.Uint64(b[48:56]))
}

// decodeNegotiateRequest reads MS-SMB2 2.2.3: StructureSize 36, DialectCount,
// SecurityMode, Reserved, Capabilities, ClientGuid, then (4 + 4 bytes of
// context offset and count or the start time) and the dialect list.
func decodeNegotiateRequest(b []byte, info *SMBInfo) {
	if len(b) < 36 || binary.LittleEndian.Uint16(b[0:2]) != 36 {
		return
	}
	count := int(binary.LittleEndian.Uint16(b[2:4]))
	info.setSigning(binary.LittleEndian.Uint16(b[4:6]))
	info.GUID = guidString(b[12:28])
	for i := 0; i < count && i < maxDialects && 36+2*i+2 <= len(b); i++ {
		info.OfferedDialects = append(info.OfferedDialects, dialectName(binary.LittleEndian.Uint16(b[36+2*i:])))
	}
}

func (i *SMBInfo) setSigning(mode uint16) {
	i.SigningEnabled = mode&0x0001 != 0
	i.SigningRequired = mode&0x0002 != 0
}

// dialectName names an SMB2 dialect revision (MS-SMB2 2.2.3).
func dialectName(d uint16) string {
	switch d {
	case 0x0202:
		return "2.0.2"
	case 0x0210:
		return "2.1"
	case 0x0300:
		return "3.0"
	case 0x0302:
		return "3.0.2"
	case 0x0311:
		return "3.1.1"
	case 0x02ff:
		return "2.x" // the wildcard a server answers an SMB1 negotiate with
	}
	return fmt.Sprintf("0x%04x", d)
}

// guidString formats a GUID in its wire layout (the first three fields little
// endian, MS-DTYP 2.3.4.2).
func guidString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	if allZero(b[:16]) {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}

// fileTime converts a Windows FILETIME (100 ns ticks since 1601-01-01 UTC) and
// returns the zero time for 0 or a value outside 1970..2262.
func fileTime(ft uint64) time.Time {
	const epochDiff = 116444736000000000 // 1601 to 1970 in 100 ns
	if ft < epochDiff || ft-epochDiff > uint64(1<<62)/100 {
		return time.Time{}
	}
	return time.Unix(0, int64(ft-epochDiff)*100).UTC()
}
