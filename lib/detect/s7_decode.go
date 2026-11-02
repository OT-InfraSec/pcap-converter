package detect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Events of the S7 decoder.
const (
	S7EventInvalidCOTP = "invalid_cotp" // the COTP header does not fit the TPKT frame
	S7EventInvalidS7   = "invalid_s7"   // the S7 PDU is cut short or inconsistent
)

// S7Setup is the parameter of Setup communication (function 0xF0).
type S7Setup struct {
	MaxAmQCalling uint16
	MaxAmQCalled  uint16
	PDULength     uint16
}

// S7Item is one item of a Read Var or Write Var request (S7ANY addressing).
type S7Item struct {
	Syntax            byte
	Area              byte
	AreaName          string
	DB                uint16
	ByteAddress       uint32
	Bit               uint8
	TransportSize     byte
	TransportSizeName string
	Length            uint16
}

// S7DataItem is one item of the data section: return code, transport size,
// length (in bits for bit, byte and integer sizes, else in bytes) and value.
type S7DataItem struct {
	ReturnCode    byte
	ReturnName    string
	TransportSize byte
	Length        uint16
	Bytes         []byte // at most 256 bytes are kept
}

// S7Module is one record of SZL 0x0011 (module identification).
type S7Module struct {
	Index       uint16
	OrderNumber string
	ModuleType  uint16
	Version     [2]uint16
}

// S7Identity is what a CPU says about itself in an SZL reply: SZL 0x001C
// (component identification: names and serial numbers by index) or SZL 0x0011
// (order numbers and versions). OrderNumber, ModuleType and Version repeat the
// first record of SZL 0x0011.
type S7Identity struct {
	Strings     map[uint16]string // SZL 0x001C: 1 system name, 2 module name, 3 plant id, 4 copyright, 5 serial number, 7 module type, 8 memory card serial
	Modules     []S7Module        // SZL 0x0011
	OrderNumber string
	ModuleType  uint16
	Version     [2]uint16
}

// S7Userdata is the parameter and data of a Userdata PDU (ROSCTR 7): requests
// and replies for system functions such as reading the SZL system state list.
type S7Userdata struct {
	Type              byte // 0 push, 4 request, 8 response
	TypeName          string
	FunctionGroup     byte
	FunctionGroupName string
	SubFunction       byte
	SubFunctionName   string
	Sequence          byte
	DataUnitRef       byte
	LastDataUnit      byte
	ErrorCode         uint16
	SZLID, SZLIndex   uint16
	Identity          *S7Identity
}

// S7Message is one decoded TPKT frame (or, for a segmented S7 PDU, the frames
// of one PDU). Connection frames carry TSAPs; data frames carry the S7 PDU.
type S7Message struct {
	COTPType byte
	COTPName string
	SrcTSAP  []byte
	DstTSAP  []byte
	Rack     int // from the called TSAP of a connection request, -1 if not given
	Slot     int
	TPDUSize int // negotiated COTP TPDU size in bytes, 0 if not given

	HasS7        bool
	Plus         *S7PlusHeader // set when the PDU is S7CommPlus (protocol id 0x72); HasS7 stays false
	ROSCTR       byte
	ROSCTRName   string
	PDURef       uint16
	ParamLen     uint16
	DataLen      uint16
	ErrorClass   byte // Ack and Ack_Data only
	ErrorCode    byte
	Function     byte
	FunctionName string
	Setup        *S7Setup
	Items        []S7Item
	Data         []S7DataItem
	PLCService   string // PLC Control and PLC Stop: the program service
	Userdata     *S7Userdata

	Events []string
}

// S7Frame is one parsed TPKT frame with its COTP header.
type S7Frame struct {
	COTPType byte
	COTPName string
	EOT      bool // data TPDU: last fragment of the S7 PDU
	SrcTSAP  []byte
	DstTSAP  []byte
	TPDUSize int
	Payload  []byte // data TPDU: the bytes after the COTP header
	Events   []string
}

var cotpNames = map[byte]string{cotpCR: "CR", cotpCC: "CC", cotpDR: "DR", cotpDC: "DC", cotpDT: "DT", cotpER: "ER"}

var s7ROSCTRNames = map[byte]string{s7Job: "Job", s7Ack: "Ack", s7AckData: "Ack_Data", s7Userdata: "Userdata"}

var s7FunctionNames = map[byte]string{
	0x00: "CPU services", 0xf0: "Setup communication", 0x04: "Read Var", 0x05: "Write Var",
	0x1a: "Request download", 0x1b: "Download block", 0x1c: "Download ended", 0x1d: "Start upload",
	0x1e: "Upload", 0x1f: "End upload", 0x28: "PLC Control", 0x29: "PLC Stop",
}

var s7AreaNames = map[byte]string{
	0x03: "System info", 0x05: "System flags", 0x06: "Analog inputs", 0x07: "Analog outputs", 0x1c: "Counters",
	0x1d: "Timers", 0x1e: "IEC counters", 0x1f: "IEC timers", 0x80: "Direct peripheral access", 0x81: "Inputs",
	0x82: "Outputs", 0x83: "Flags", 0x84: "Data block", 0x85: "Instance data block", 0x86: "Local data", 0x87: "Previous local data",
}

var s7TransportSizeNames = map[byte]string{
	0x01: "BIT", 0x02: "BYTE", 0x03: "CHAR", 0x04: "WORD", 0x05: "INT", 0x06: "DWORD", 0x07: "DINT", 0x08: "REAL",
	0x09: "DATE", 0x0a: "TOD", 0x0b: "TIME", 0x1c: "COUNTER", 0x1d: "TIMER", 0x1e: "IEC TIMER",
}

var s7ReturnNames = map[byte]string{
	0xff: "Success", 0x00: "Reserved", 0x01: "Hardware fault", 0x03: "Accessing the object not allowed",
	0x05: "Invalid address", 0x06: "Data type not supported", 0x07: "Data type inconsistent", 0x0a: "Object does not exist",
}

var s7UserdataTypeNames = map[byte]string{0: "Push", 4: "Request", 8: "Response"}

var s7UserdataGroupNames = map[byte]string{
	1: "Programmer commands", 2: "Cyclic data", 3: "Block functions", 4: "CPU functions", 5: "Security",
	6: "PBC BSEND/BRECV", 7: "Time functions",
}

var s7UserdataSubfunctions = map[[2]byte]string{
	{3, 1}: "List blocks", {3, 2}: "List blocks of type", {3, 3}: "Get block info",
	{4, 1}: "Read SZL", {4, 2}: "Message service", {4, 3}: "Diagnostic message",
	{7, 1}: "Read clock", {7, 2}: "Set clock", {7, 3}: "Read clock (following)", {7, 4}: "Set clock",
}

// S7FrameSize returns the size of the TPKT frame that starts at b: 0 when b is
// too short to tell, -1 when b does not start with a valid TPKT header (version
// 3, a length that leaves room for a COTP header).
func S7FrameSize(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	if b[0] != 3 {
		return -1
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < 6 {
		return -1
	}
	return n
}

// ParseS7Frame parses the TPKT and COTP headers of the frame at the start of
// b. It returns false when the whole frame is not there or the TPKT header is
// invalid. A COTP header that does not fit is reported as an event.
func ParseS7Frame(b []byte) (S7Frame, int, bool) {
	size := S7FrameSize(b)
	if size <= 0 || len(b) < size {
		return S7Frame{}, 0, false
	}
	f := S7Frame{}
	body := b[4:size]
	li := int(body[0])
	if 1+li > len(body) || li < 1 {
		// The COTP length does not fit the frame. The TPKT length is at least 6,
		// so the type byte is there; name it as far as it can be told.
		f.COTPType = body[1] & 0xf0
		if n, ok := cotpNames[f.COTPType]; ok {
			f.COTPName = n
		} else {
			f.COTPName = fmt.Sprintf("unknown-%d", f.COTPType)
		}
		f.Events = []string{S7EventInvalidCOTP}
		return f, size, true
	}
	hdr := body[1 : 1+li]
	f.COTPType = hdr[0] & 0xf0
	if n, ok := cotpNames[f.COTPType]; ok {
		f.COTPName = n
	} else {
		f.COTPName = fmt.Sprintf("unknown-%d", f.COTPType)
	}
	switch f.COTPType {
	case cotpDT:
		if li < 2 {
			f.Events = []string{S7EventInvalidCOTP}
			break
		}
		f.EOT = hdr[1]&0x80 != 0
		f.Payload = body[1+li:]
	case cotpCR, cotpCC:
		if li < 6 {
			f.Events = []string{S7EventInvalidCOTP}
			break
		}
		// type, destination ref (2), source ref (2), class, then parameters.
		params := hdr[6:]
		for len(params) >= 2 {
			code, n := params[0], int(params[1])
			if len(params) < 2+n {
				f.Events = []string{S7EventInvalidCOTP}
				break
			}
			v := params[2 : 2+n]
			switch {
			case code == 0xc0 && n == 1:
				if v[0] < 32 {
					f.TPDUSize = 1 << v[0]
				}
			case code == 0xc1:
				f.SrcTSAP = append([]byte(nil), v...)
			case code == 0xc2:
				f.DstTSAP = append([]byte(nil), v...)
			}
			params = params[2+n:]
		}
	}
	return f, size, true
}

// DecodeS7 decodes the TPKT frame at the start of b and returns its size. A
// data TPDU is decoded as a whole S7 PDU only when it is the last fragment; use
// ParseS7Frame and MessageFromFrames to join fragments. It returns false when b
// does not yet hold the whole frame or is not TPKT.
func DecodeS7(b []byte) (S7Message, int, bool) {
	f, n, ok := ParseS7Frame(b)
	if !ok {
		return S7Message{}, 0, false
	}
	return MessageFromFrames([]S7Frame{f}), n, true
}

// MessageFromFrames builds the message of one frame, or of the data frames of
// one segmented S7 PDU (all but the last without the EOT bit).
func MessageFromFrames(frames []S7Frame) S7Message {
	last := frames[len(frames)-1]
	m := S7Message{
		COTPType: last.COTPType, COTPName: last.COTPName, SrcTSAP: last.SrcTSAP, DstTSAP: last.DstTSAP,
		TPDUSize: last.TPDUSize, Rack: -1, Slot: -1,
	}
	for _, f := range frames {
		m.Events = append(m.Events, f.Events...)
	}
	if len(m.DstTSAP) == 2 {
		m.Rack, m.Slot = int(m.DstTSAP[1]>>5), int(m.DstTSAP[1]&0x1f)
	}
	if last.COTPType != cotpDT || !last.EOT || len(m.Events) > 0 {
		return m
	}
	var pdu []byte
	if len(frames) == 1 {
		pdu = last.Payload
	} else {
		for _, f := range frames {
			pdu = append(pdu, f.Payload...)
		}
	}
	if len(pdu) > 0 && pdu[0] == S7PlusProtocolID {
		if !decodeS7PlusPDU(&m, pdu) {
			m.Events = append(m.Events, S7PlusEventInvalid)
		}
		return m
	}
	if len(pdu) == 0 || pdu[0] != S7ProtocolID {
		return m // data of another protocol over COTP
	}
	m.HasS7 = true
	if !decodeS7PDU(&m, pdu) {
		m.Events = append(m.Events, S7EventInvalidS7)
	}
	return m
}

func decodeS7PDU(m *S7Message, b []byte) bool {
	if len(b) < 10 {
		return false
	}
	be := binary.BigEndian
	m.ROSCTR = b[1]
	if n, ok := s7ROSCTRNames[m.ROSCTR]; ok {
		m.ROSCTRName = n
	} else {
		m.ROSCTRName = fmt.Sprintf("unknown-%d", m.ROSCTR)
	}
	m.PDURef = be.Uint16(b[4:6])
	m.ParamLen, m.DataLen = be.Uint16(b[6:8]), be.Uint16(b[8:10])
	hdr := 10
	if m.ROSCTR == s7Ack || m.ROSCTR == s7AckData {
		if len(b) < 12 {
			return false
		}
		m.ErrorClass, m.ErrorCode = b[10], b[11]
		hdr = 12
	}
	if len(b) < hdr+int(m.ParamLen)+int(m.DataLen) {
		return false
	}
	param := b[hdr : hdr+int(m.ParamLen)]
	data := b[hdr+int(m.ParamLen) : hdr+int(m.ParamLen)+int(m.DataLen)]
	if m.ROSCTR == s7Userdata {
		return decodeS7Userdata(m, param, data)
	}
	if len(param) == 0 {
		return true
	}
	m.Function = param[0]
	if n, ok := s7FunctionNames[m.Function]; ok {
		m.FunctionName = n
	} else {
		m.FunctionName = fmt.Sprintf("unknown-%d", m.Function)
	}
	switch m.Function {
	case 0xf0:
		if len(param) < 8 {
			return false
		}
		m.Setup = &S7Setup{be.Uint16(param[2:4]), be.Uint16(param[4:6]), be.Uint16(param[6:8])}
	case 0x04, 0x05:
		if len(param) < 2 {
			return false
		}
		count := int(param[1])
		if m.ROSCTR == s7Job {
			items, ok := decodeS7Items(param[2:], count)
			m.Items = items // what decoded before a failure is still reported
			if !ok {
				return false
			}
		}
		if len(data) > 0 {
			if m.Function == 0x05 && m.ROSCTR == s7AckData {
				for _, rc := range data { // a write reply is one return code per item
					m.Data = append(m.Data, S7DataItem{ReturnCode: rc, ReturnName: s7ReturnNames[rc]})
				}
			} else {
				items, ok := decodeS7DataItems(data)
				m.Data = items
				if !ok {
					return false
				}
			}
		}
	case 0x28:
		// function, 7 reserved bytes, argument length, argument, service name
		if len(param) >= 10 {
			argLen := int(be.Uint16(param[8:10]))
			if rest := param[10:]; len(rest) >= argLen+1 {
				rest = rest[argLen:]
				if n := int(rest[0]); len(rest) >= 1+n {
					m.PLCService = string(rest[1 : 1+n])
				}
			}
		}
	case 0x29:
		// function, 5 reserved bytes, service name
		if len(param) >= 7 {
			if n := int(param[6]); len(param) >= 7+n {
				m.PLCService = string(param[7 : 7+n])
			}
		}
	}
	return true
}

func decodeS7Items(b []byte, count int) ([]S7Item, bool) {
	var items []S7Item
	for i := 0; i < count; i++ {
		if len(b) < 2 || b[0] != 0x12 {
			return items, false
		}
		n := int(b[1])
		if len(b) < 2+n || n < 1 {
			return items, false
		}
		spec := b[2 : 2+n]
		b = b[2+n:]
		it := S7Item{Syntax: spec[0]}
		if it.Syntax == 0x10 { // S7ANY
			if n != 10 {
				return items, false
			}
			it.TransportSize = spec[1]
			it.TransportSizeName = s7TransportSizeNames[spec[1]]
			it.Length = binary.BigEndian.Uint16(spec[2:4])
			it.DB = binary.BigEndian.Uint16(spec[4:6])
			it.Area = spec[6]
			it.AreaName = s7AreaNames[spec[6]]
			addr := uint32(spec[7])<<16 | uint32(spec[8])<<8 | uint32(spec[9])
			it.ByteAddress, it.Bit = addr>>3, uint8(addr&7)
		}
		items = append(items, it)
	}
	return items, true
}

func decodeS7DataItems(b []byte) ([]S7DataItem, bool) {
	var items []S7DataItem
	for len(b) > 0 {
		if len(b) < 4 {
			// Stray bytes after complete items are ignored; a cut-off first item is not.
			return items, len(items) > 0
		}
		it := S7DataItem{ReturnCode: b[0], TransportSize: b[1], Length: binary.BigEndian.Uint16(b[2:4])}
		it.ReturnName = s7ReturnNames[it.ReturnCode]
		n := int(it.Length)
		switch it.TransportSize {
		case 3, 4, 5: // the length is in bits
			n = (n + 7) / 8
		}
		b = b[4:]
		if len(b) < n {
			return items, false
		}
		keep := b[:n]
		if len(keep) > 256 {
			keep = keep[:256]
		}
		it.Bytes = append([]byte(nil), keep...)
		items = append(items, it)
		b = b[n:]
		if n%2 == 1 && len(b) > 0 { // a fill byte pads the item to a word unless it is the last
			b = b[1:]
		}
	}
	return items, true
}

func decodeS7Userdata(m *S7Message, param, data []byte) bool {
	if len(param) < 4 || param[0] != 0 || param[1] != 1 || param[2] != 0x12 {
		return false
	}
	plen := int(param[3])
	if plen < 4 || len(param) < 4+plen {
		return false
	}
	p := param[4 : 4+plen]
	u := &S7Userdata{Type: p[1] >> 4, FunctionGroup: p[1] & 0x0f, SubFunction: p[2], Sequence: p[3]}
	if plen >= 8 {
		u.DataUnitRef, u.LastDataUnit, u.ErrorCode = p[4], p[5], binary.BigEndian.Uint16(p[6:8])
	}
	u.TypeName = s7UserdataTypeNames[u.Type]
	u.FunctionGroupName = s7UserdataGroupNames[u.FunctionGroup]
	u.SubFunctionName = s7UserdataSubfunctions[[2]byte{u.FunctionGroup, u.SubFunction}]
	m.Userdata = u
	m.Function, m.FunctionName = u.SubFunction, u.SubFunctionName
	if items, ok := decodeS7DataItems(data); ok {
		m.Data = items
	}

	if u.FunctionGroup == 4 && u.SubFunction == 1 && len(data) >= 4 {
		body := data[4:]
		if n := int(binary.BigEndian.Uint16(data[2:4])); n < len(body) {
			body = body[:n]
		}
		decodeS7SZL(u, body)
	}
	return true
}

func decodeS7SZL(u *S7Userdata, b []byte) {
	be := binary.BigEndian
	if len(b) < 4 {
		return
	}
	u.SZLID, u.SZLIndex = be.Uint16(b[0:2]), be.Uint16(b[2:4])
	if u.Type != 8 || len(b) < 8 {
		return
	}
	recLen, count := int(be.Uint16(b[4:6])), int(be.Uint16(b[6:8]))
	recs := b[8:]
	if recLen == 0 || count == 0 {
		return
	}
	id := &S7Identity{}
	switch u.SZLID {
	case 0x001c:
		id.Strings = map[uint16]string{}
		for i := 0; i < count && len(recs) >= recLen && recLen >= 34; i++ {
			id.Strings[be.Uint16(recs[0:2])] = trimS7String(recs[2:34])
			recs = recs[recLen:]
		}
		if len(id.Strings) == 0 {
			return
		}
	case 0x0011:
		for i := 0; i < count && len(recs) >= recLen && recLen >= 28; i++ {
			id.Modules = append(id.Modules, S7Module{
				Index: be.Uint16(recs[0:2]), OrderNumber: trimS7String(recs[2:22]), ModuleType: be.Uint16(recs[22:24]),
				Version: [2]uint16{be.Uint16(recs[24:26]), be.Uint16(recs[26:28])},
			})
			recs = recs[recLen:]
		}
		if len(id.Modules) == 0 {
			return
		}
		first := id.Modules[0]
		id.OrderNumber, id.ModuleType, id.Version = first.OrderNumber, first.ModuleType, first.Version
	default:
		return
	}
	u.Identity = id
}

func trimS7String(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimRight(string(b), " ")
}
