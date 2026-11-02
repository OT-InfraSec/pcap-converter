package detect

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ENIPEventInvalidPDU is raised when a complete encapsulation message has a
// payload that does not parse (Suricata: enip.invalid_pdu).
const ENIPEventInvalidPDU = "invalid_pdu"

// ENIPSessionRegistration is the payload of a RegisterSession request or reply.
type ENIPSessionRegistration struct {
	ProtocolVersion uint16
	Options         uint16
}

// ENIPIdentity is a ListIdentity reply item (ODVA, EtherNet/IP Adaptation of
// CIP, 2-4.2): the identity object attributes of a device plus its address.
type ENIPIdentity struct {
	ProtocolVersion uint16
	IP              string
	Port            uint16
	VendorID        uint16
	DeviceType      uint16
	ProductCode     uint16
	RevisionMajor   uint8
	RevisionMinor   uint8
	Status          uint16
	Serial          uint32
	ProductName     string
	State           uint8
}

// ENIPServices is a ListServices reply item.
type ENIPServices struct {
	ProtocolVersion uint16
	Capabilities    uint16
	Name            string
}

// ENIPItem is one item of a Common Packet Format list.
type ENIPItem struct {
	Type     uint16
	Length   uint16
	Identity *ENIPIdentity
	Services *ENIPServices
	CIP      *CIPMessage
}

// CIPPathSegment is one logical segment of a CIP path.
type CIPPathSegment struct {
	Type  byte
	Kind  string // class, instance, attribute, member, connection point, special, or ""
	Value uint32
}

// CIPMessage is a CIP request or response (ODVA, CIP Volume 1, chapter 2-4).
type CIPMessage struct {
	Service     byte // without the response bit
	ServiceName string
	IsResponse  bool
	Sequence    *uint16 // connected messages only

	// Requests.
	Path           []CIPPathSegment
	Class          int // -1 when the path has none
	Instance       int
	Attribute      int
	Symbol         string // ANSI symbolic segment: a Logix tag name
	PathTruncated  bool   // a segment type this decoder does not read ended the path
	AttributeList  []uint16
	FirstAttribute int // first attribute of a Set Attribute List, -1 when none

	// Responses.
	GeneralStatus     byte
	GeneralStatusName string
	ExtendedStatus    []uint16

	// Multiple Service Packet: the embedded messages, one level deep.
	Multiple []*CIPMessage
}

// ENIPMessage is one decoded encapsulation message.
type ENIPMessage struct {
	Command     uint16
	CommandName string
	Length      uint16
	Session     uint32
	Status      uint32
	StatusName  string
	Context     uint64
	Options     uint32

	RegisterSession *ENIPSessionRegistration
	Items           []ENIPItem
	Handle          uint32 // SendRRData, SendUnitData
	Timeout         uint16
	CIP             *CIPMessage // the first CIP message among Items

	Invalid bool
	Events  []string
}

var enipCommandNames = map[uint16]string{
	ENIPNop: "nop", ENIPListServices: "list_services", ENIPListIdentity: "list_identity",
	ENIPListInterfaces: "list_interfaces", ENIPRegisterSession: "register_session",
	ENIPUnregisterSession: "unregister_session", ENIPSendRRData: "send_r_r_data",
	ENIPSendUnitData: "send_unit_data", ENIPIndicateStatus: "indicate_status", ENIPCancel: "cancel",
}

var enipStatusNames = map[uint32]string{
	ENIPStatusSuccess: "success", ENIPStatusInvalidCommand: "invalid_cmd", ENIPStatusNoResources: "no_resources",
	ENIPStatusIncorrectData: "incorrect_data", ENIPStatusInvalidSession: "invalid_session",
	ENIPStatusInvalidLength: "invalid_length", ENIPStatusUnsupportedProtRev: "unsupported_prot_rev",
	ENIPStatusEncapHeaderError: "encap_header_error",
}

// CIP general status codes (CIP Volume 1, table 3-5.2).
var cipStatusNames = map[byte]string{
	0x00: "Success", 0x01: "Connection Failure", 0x02: "Resource Unavailable", 0x03: "Invalid Parameter Value",
	0x04: "Path Segment Error", 0x05: "Path Destination Unknown", 0x06: "Partial Transfer", 0x07: "Connection Lost",
	0x08: "Service Not Supported", 0x09: "Invalid Attribute Value", 0x0A: "Attribute List Error",
	0x0B: "Already In Requested Mode/State", 0x0C: "Object State Conflict", 0x0D: "Object Already Exists",
	0x0E: "Attribute Not Settable", 0x0F: "Privilege Violation", 0x10: "Device State Conflict",
	0x11: "Reply Data Too Large", 0x12: "Fragmentation Of A Primitive Value", 0x13: "Not Enough Data",
	0x14: "Attribute Not Supported", 0x15: "Too Much Data", 0x16: "Object Does Not Exist",
	0x17: "Service Fragmentation Sequence Not In Progress", 0x18: "No Stored Attribute Data",
	0x19: "Store Operation Failure", 0x1A: "Routing Failure, Request Packet Too Large",
	0x1B: "Routing Failure, Response Packet Too Large", 0x1C: "Missing Attribute List Entry Data",
	0x1D: "Invalid Attribute Value List", 0x1E: "Embedded Service Error", 0x1F: "Vendor Specific Error",
	0x20: "Invalid Parameter", 0x21: "Write-Once Value Or Medium Already Written", 0x22: "Invalid Reply Received",
	0x23: "Buffer Overflow", 0x24: "Invalid Message Format", 0x25: "Key Failure In Path", 0x26: "Path Size Invalid",
	0x27: "Unexpected Attribute In List", 0x28: "Invalid Member ID", 0x29: "Member Not Settable",
	0x2A: "Group 2 Only Server General Failure", 0x2C: "Attribute Not Gettable",
}

// CIP common services (CIP Volume 1, table 3-5.1): the same for every object.
var cipCommonServices = map[byte]string{
	0x01: "Get Attributes All", 0x02: "Set Attributes All", 0x03: "Get Attribute List", 0x04: "Set Attribute List",
	0x05: "Reset", 0x06: "Start", 0x07: "Stop", 0x08: "Create", 0x09: "Delete", 0x0A: "Multiple Service Packet",
	0x0D: "Apply Attributes", 0x0E: "Get Attribute Single", 0x10: "Set Attribute Single",
	0x11: "Find Next Object Instance", 0x15: "Restore", 0x16: "Save", 0x17: "No Operation", 0x18: "Get Member",
	0x19: "Set Member", 0x1A: "Insert Member", 0x1B: "Remove Member", 0x1C: "Group Sync",
}

// Object-specific services. The same code means different things in different
// classes, so the name depends on the class from the request path.
const (
	cipClassConnectionManager = 0x06
	cipClassPCCC              = 0x67
	cipClassSymbol            = 0x6B
	cipClassTemplate          = 0x6C
)

var cipConnectionManagerServices = map[byte]string{
	0x4E: "Forward Close", 0x52: "Unconnected Send", 0x54: "Forward Open", 0x56: "Get Connection Data",
	0x57: "Search Connection Data", 0x5A: "Get Connection Owner", 0x5B: "Large Forward Open",
}

// Rockwell Logix tag services, sent to the Symbol and Template classes or to a
// symbolic path. Vendor documentation, not part of the CIP specification.
var cipLogixServices = map[byte]string{
	0x4C: "Read Tag", 0x4D: "Write Tag", 0x4E: "Read Modify Write Tag", 0x52: "Read Tag Fragmented",
	0x53: "Write Tag Fragmented", 0x55: "Get Instance Attribute List",
}

// CIPServiceName names a service code for the object class it is sent to
// (class -1: unknown). It returns "" for a code that is object specific and not
// known for that class.
func CIPServiceName(service byte, class int, symbolic bool) string {
	if n, ok := cipCommonServices[service]; ok {
		return n
	}
	switch {
	case class == cipClassConnectionManager:
		return cipConnectionManagerServices[service]
	case class == cipClassPCCC && service == 0x4B:
		return "Execute PCCC"
	case class == cipClassSymbol || class == cipClassTemplate || symbolic:
		return cipLogixServices[service]
	}
	return ""
}

// ENIPPDUSize returns the size of the encapsulation message that starts at b,
// from the header's length field, or 0 when b is shorter than a header.
func ENIPPDUSize(b []byte) int {
	if len(b) < ENIPHeaderLen {
		return 0
	}
	return ENIPHeaderLen + int(binary.LittleEndian.Uint16(b[2:4]))
}

// DecodeENIP decodes the encapsulation message at the start of b and returns
// the number of bytes it occupies. It returns false when b does not yet hold
// the whole message. A message whose payload does not parse is returned with
// Invalid set and the event invalid_pdu: the frame boundaries are still known.
func DecodeENIP(b []byte) (ENIPMessage, int, bool) {
	size := ENIPPDUSize(b)
	if size == 0 || len(b) < size {
		return ENIPMessage{}, 0, false
	}
	le := binary.LittleEndian
	m := ENIPMessage{
		Command: le.Uint16(b[0:2]), Length: le.Uint16(b[2:4]), Session: le.Uint32(b[4:8]),
		Status: le.Uint32(b[8:12]), Context: le.Uint64(b[12:20]), Options: le.Uint32(b[20:24]),
	}
	if n, ok := enipCommandNames[m.Command]; ok {
		m.CommandName = n
	} else {
		m.CommandName = fmt.Sprintf("unknown-%d", m.Command)
	}
	if n, ok := enipStatusNames[m.Status]; ok {
		m.StatusName = n
	} else {
		m.StatusName = fmt.Sprintf("unknown-%d", m.Status)
	}
	data := b[ENIPHeaderLen:size]

	ok := true
	switch m.Command {
	case ENIPRegisterSession:
		if len(data) >= 4 {
			m.RegisterSession = &ENIPSessionRegistration{le.Uint16(data[0:2]), le.Uint16(data[2:4])}
		} else {
			ok = false
		}
	case ENIPListServices, ENIPListInterfaces, ENIPListIdentity:
		// The request is empty, the reply carries items.
		if len(data) > 0 {
			m.Items, ok = decodeENIPItems(data)
		}
	case ENIPSendRRData, ENIPSendUnitData:
		if len(data) < 8 {
			ok = false
			break
		}
		m.Handle, m.Timeout = le.Uint32(data[0:4]), le.Uint16(data[4:6])
		m.Items, ok = decodeENIPItems(data[6:])
		if ok {
			for _, it := range m.Items {
				if it.CIP != nil {
					m.CIP = it.CIP
					break
				}
			}
		}
	}
	if !ok {
		m.Invalid = true
		m.Events = []string{ENIPEventInvalidPDU}
		m.Items, m.CIP = nil, nil
	}
	return m, size, true
}

// decodeENIPItems parses a Common Packet Format list: count, then items of
// type, length, data. It fails like Suricata's parser does: a count or length
// larger than the data, a short identity or services item, or a CIP message
// that is cut short.
func decodeENIPItems(b []byte) ([]ENIPItem, bool) {
	le := binary.LittleEndian
	if len(b) < 2 {
		return nil, false
	}
	count := int(le.Uint16(b[0:2]))
	b = b[2:]
	var items []ENIPItem
	for i := 0; i < count; i++ {
		if len(b) < 4 {
			return nil, false
		}
		it := ENIPItem{Type: le.Uint16(b[0:2]), Length: le.Uint16(b[2:4])}
		if len(b) < 4+int(it.Length) {
			return nil, false
		}
		data := b[4 : 4+int(it.Length)]
		b = b[4+int(it.Length):]
		var ok bool
		switch it.Type {
		case 0x0c:
			it.Identity, ok = decodeENIPIdentity(data)
		case 0x100:
			it.Services, ok = decodeENIPServices(data)
		case 0xb1: // connected data: sequence number, then CIP
			if len(data) < 2 {
				return nil, false
			}
			seq := le.Uint16(data[0:2])
			it.CIP, ok = decodeCIP(data[2:], true)
			if ok {
				it.CIP.Sequence = &seq
			}
		case 0xb2: // unconnected data
			it.CIP, ok = decodeCIP(data, true)
		default:
			ok = true
		}
		if !ok {
			return nil, false
		}
		items = append(items, it)
	}
	return items, true
}

func decodeENIPIdentity(d []byte) (*ENIPIdentity, bool) {
	le := binary.LittleEndian
	// version(2) sockaddr(16) vendor(2) type(2) code(2) rev(2) status(2) serial(4) namelen(1)
	if len(d) < 2+16+2+2+2+2+2+4+1 {
		return nil, false
	}
	id := &ENIPIdentity{ProtocolVersion: le.Uint16(d[0:2])}
	sock := d[2:18] // sockaddr_in, big endian
	id.Port = binary.BigEndian.Uint16(sock[2:4])
	id.IP = net.IP(sock[4:8]).String()
	d = d[18:]
	id.VendorID, id.DeviceType, id.ProductCode = le.Uint16(d[0:2]), le.Uint16(d[2:4]), le.Uint16(d[4:6])
	id.RevisionMajor, id.RevisionMinor = d[6], d[7]
	id.Status = le.Uint16(d[8:10])
	id.Serial = le.Uint32(d[10:14])
	n := int(d[14])
	d = d[15:]
	if len(d) < n+1 {
		return nil, false
	}
	id.ProductName = string(d[:n])
	id.State = d[n]
	return id, true
}

func decodeENIPServices(d []byte) (*ENIPServices, bool) {
	if len(d) < 4+16 {
		return nil, false
	}
	name := d[4:20]
	if i := strings.IndexByte(string(name), 0); i >= 0 {
		name = name[:i]
	}
	return &ENIPServices{
		ProtocolVersion: binary.LittleEndian.Uint16(d[0:2]),
		Capabilities:    binary.LittleEndian.Uint16(d[2:4]),
		Name:            string(name),
	}, true
}

const (
	cipGetAttributeList = 0x03
	cipSetAttributeList = 0x04
	cipMultipleService  = 0x0a
	cipSegmentKindLimit = 8
)

// decodeCIP parses one CIP message. multi allows a Multiple Service Packet
// (one level of nesting only, as in Suricata).
func decodeCIP(b []byte, multi bool) (*CIPMessage, bool) {
	if len(b) < 1 {
		return nil, false
	}
	m := &CIPMessage{Class: -1, Instance: -1, Attribute: -1, FirstAttribute: -1}
	m.IsResponse = b[0]&0x80 != 0
	m.Service = b[0] & 0x7f
	b = b[1:]
	if m.IsResponse {
		return decodeCIPResponse(m, b, multi)
	}
	return decodeCIPRequest(m, b, multi)
}

func decodeCIPRequest(m *CIPMessage, b []byte, multi bool) (*CIPMessage, bool) {
	le := binary.LittleEndian
	if len(b) < 1 {
		return nil, false
	}
	words := int(b[0])
	if len(b) < 1+2*words {
		return nil, false
	}
	path := b[1 : 1+2*words]
	rest := b[1+2*words:]
	parseCIPPath(m, path)
	m.ServiceName = CIPServiceName(m.Service, m.Class, m.Symbol != "")

	switch m.Service {
	case cipGetAttributeList:
		if len(rest) < 2 {
			return nil, false
		}
		n := int(le.Uint16(rest[0:2]))
		if len(rest) < 2+2*n {
			return nil, false
		}
		for i := 0; i < n; i++ {
			m.AttributeList = append(m.AttributeList, le.Uint16(rest[2+2*i:]))
		}
	case cipSetAttributeList:
		if len(rest) < 2 {
			return nil, false
		}
		if n := le.Uint16(rest[0:2]); n > 0 {
			if len(rest) < 4 {
				return nil, false
			}
			m.FirstAttribute = int(le.Uint16(rest[2:4]))
		}
	case cipMultipleService:
		if multi {
			return decodeCIPMultiple(m, rest)
		}
	}
	return m, true
}

func decodeCIPResponse(m *CIPMessage, b []byte, multi bool) (*CIPMessage, bool) {
	if len(b) < 3 {
		return nil, false
	}
	m.GeneralStatus = b[1]
	m.GeneralStatusName = cipStatusNames[m.GeneralStatus]
	words := int(b[2])
	if len(b) < 3+2*words {
		return nil, false
	}
	for i := 0; i < words; i++ {
		m.ExtendedStatus = append(m.ExtendedStatus, binary.LittleEndian.Uint16(b[3+2*i:]))
	}
	rest := b[3+2*words:]
	m.ServiceName = CIPServiceName(m.Service, -1, false)
	if m.Service == cipMultipleService && multi {
		return decodeCIPMultiple(m, rest)
	}
	return m, true
}

// decodeCIPMultiple reads a Multiple Service Packet body: a count, a list of
// offsets (from the count field) and the embedded messages. Offsets must
// increase and stay inside the body.
func decodeCIPMultiple(m *CIPMessage, body []byte) (*CIPMessage, bool) {
	le := binary.LittleEndian
	if len(body) < 2 {
		return nil, false
	}
	n := int(le.Uint16(body[0:2]))
	if len(body) < 2+2*n {
		return nil, false
	}
	consumed := 2 + 2*n
	for i := 0; i < n; i++ {
		off := int(le.Uint16(body[2+2*i:]))
		if off < consumed || off >= len(body) {
			return nil, false
		}
		sub, ok := decodeCIPWithSize(body[off:])
		if !ok {
			return nil, false
		}
		m.Multiple = append(m.Multiple, sub.msg)
		consumed = off + sub.size
	}
	return m, true
}

type cipSized struct {
	msg  *CIPMessage
	size int
}

// decodeCIPWithSize parses an embedded message and reports how many bytes its
// structure used, which is what the next offset must not undercut.
func decodeCIPWithSize(b []byte) (cipSized, bool) {
	m, ok := decodeCIP(b, false)
	if !ok {
		return cipSized{}, false
	}
	return cipSized{msg: m, size: cipConsumed(b, m)}, true
}

// cipConsumed is the length of the parsed part of b for message m.
func cipConsumed(b []byte, m *CIPMessage) int {
	if m.IsResponse {
		return 4 + 2*len(m.ExtendedStatus)
	}
	n := 2 + 2*int(b[1])
	switch m.Service {
	case cipGetAttributeList:
		n += 2 + 2*len(m.AttributeList)
	case cipSetAttributeList:
		n += 2
		if m.FirstAttribute >= 0 {
			n += 2
		}
	}
	return n
}

// parseCIPPath reads logical segments (8, 16 and 32 bit values) and ANSI
// symbolic segments. It stops at any other segment type and marks the path
// truncated: that is not a malformed message.
func parseCIPPath(m *CIPMessage, p []byte) {
	le := binary.LittleEndian
	for len(p) > 0 {
		t := p[0]
		switch {
		case t == 0x91: // ANSI extended symbol: length, characters padded to a word
			if len(p) < 2 || len(p) < 2+int(p[1]) {
				m.PathTruncated = true
				return
			}
			n := int(p[1])
			m.Symbol = strings.TrimRight(string(p[2:2+n]), "\x00")
			adv := 2 + n
			if n%2 == 1 {
				adv++
			}
			if adv > len(p) {
				adv = len(p)
			}
			p = p[adv:]
			continue
		case t>>5 != 1: // not a logical segment
			m.PathTruncated = true
			return
		}
		var v uint32
		switch t & 3 {
		case 0:
			if len(p) < 2 {
				m.PathTruncated = true
				return
			}
			v, p = uint32(p[1]), p[2:]
		case 1:
			if len(p) < 4 {
				m.PathTruncated = true
				return
			}
			v, p = uint32(le.Uint16(p[2:4])), p[4:]
		case 2:
			if len(p) < 6 {
				m.PathTruncated = true
				return
			}
			v, p = le.Uint32(p[2:6]), p[6:]
		default:
			m.PathTruncated = true
			return
		}
		seg := CIPPathSegment{Type: t, Value: v}
		switch t >> 2 {
		case 8:
			seg.Kind = "class"
			m.Class = int(v)
		case 9:
			seg.Kind = "instance"
			m.Instance = int(v)
		case 10:
			seg.Kind = "member"
		case 11:
			seg.Kind = "connection point"
		case 12:
			seg.Kind = "attribute"
			m.Attribute = int(v)
		case 13:
			seg.Kind = "special"
		}
		m.Path = append(m.Path, seg)
	}
}
