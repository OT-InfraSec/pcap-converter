package detect

import "encoding/binary"

// Events of the DNP3 decoder, named after Suricata's.
const (
	DNP3EventLenTooSmall     = "len_too_small"
	DNP3EventBadLinkCRC      = "bad_link_crc"
	DNP3EventBadTransportCRC = "bad_transport_crc" // a data block CRC, as in Suricata
	DNP3EventMalformed       = "malformed"
	DNP3EventUnknownObject   = "unknown_object"
	DNP3EventTooManyObjects  = "too_many_objects"
	DNP3EventTooLongReass    = "too_long_reassembly"
)

const (
	dnp3MaxObjects  = 256
	dnp3MaxFragment = 65535
)

// DNP3Frame is one parsed link frame. UserData has the block CRCs removed.
type DNP3Frame struct {
	Length   byte
	Control  byte
	Dest     uint16
	Src      uint16
	UserData []byte
	Events   []string
	// Invalid is set when the header CRC is wrong: nothing in the frame is
	// trusted, no user data is returned, and the bytes used end at the next
	// possible frame start, as in Suricata.
	Invalid bool
}

// FromMaster is the DIR bit.
func (f DNP3Frame) FromMaster() bool { return f.Control&0x80 != 0 }

// Primary is the PRM bit.
func (f DNP3Frame) Primary() bool { return f.Control&0x40 != 0 }

// LinkFunction is the low nibble of the control byte.
func (f DNP3Frame) LinkFunction() byte { return f.Control & 0x0f }

// DNP3FrameSize returns the size of the frame that starts buf: the header plus
// user data plus block CRCs. It returns -1 if buf does not start like a frame,
// and 0 if more bytes are needed to tell.
func DNP3FrameSize(buf []byte) int {
	if len(buf) >= 1 && buf[0] != dnp3Start0 || len(buf) >= 2 && buf[1] != dnp3Start1 {
		return -1
	}
	if len(buf) < 3 {
		return 0
	}
	if buf[2] < dnp3MinLen {
		return -1
	}
	n := int(buf[2]) - dnp3MinLen
	return dnp3HeaderLen + n + 2*((n+dnp3BlockSize-1)/dnp3BlockSize)
}

// DNP3Resync returns how far to skip from the start of buf to the next
// possible frame start (the bytes 0x05 0x64), at least one. If there is none, it
// consumes everything except a final 0x05 that the next segment could complete.
func DNP3Resync(buf []byte) int {
	skip := 1
	for skip+1 < len(buf) {
		if buf[skip] == dnp3Start0 && buf[skip+1] == dnp3Start1 {
			return skip
		}
		skip++
	}
	if skip < len(buf) && buf[skip] != dnp3Start0 {
		skip++
	}
	return skip
}

// ParseDNP3Frame parses the frame at the start of buf and returns the bytes it
// used. ok is false when buf is not a frame start or the frame is incomplete.
//
// Like Suricata: a wrong header CRC makes the frame Invalid (see DNP3Frame); a
// frame whose data block CRC is wrong keeps its header but loses its user data;
// a user data frame without room for a transport header is flagged
// len_too_small. (Suricata also rejects frames shorter than a transport plus an
// application header, which would flag a legitimate one-byte final segment.)
func ParseDNP3Frame(buf []byte) (DNP3Frame, int, bool) {
	size := DNP3FrameSize(buf)
	if size < 0 || len(buf) < dnp3HeaderLen {
		return DNP3Frame{}, 0, false
	}
	f := DNP3Frame{
		Length:  buf[2],
		Control: buf[3],
		Dest:    binary.LittleEndian.Uint16(buf[4:6]),
		Src:     binary.LittleEndian.Uint16(buf[6:8]),
	}
	if dnp3CRC(buf[:8]) != binary.LittleEndian.Uint16(buf[8:10]) {
		f.Events = append(f.Events, DNP3EventBadLinkCRC)
		f.Invalid = true
		return f, DNP3Resync(buf), true
	}
	if len(buf) < size {
		return DNP3Frame{}, 0, false
	}
	rest := buf[dnp3HeaderLen:size]
	badBlock := false
	for len(rest) > 0 {
		n := len(rest) - 2
		if n > dnp3BlockSize {
			n = dnp3BlockSize
		}
		block := rest[:n]
		if dnp3CRC(block) != binary.LittleEndian.Uint16(rest[n:n+2]) {
			badBlock = true
		}
		f.UserData = append(f.UserData, block...)
		rest = rest[n+2:]
	}
	userData := f.Primary() && (f.LinkFunction() == 3 || f.LinkFunction() == 4)
	switch {
	case userData && f.Length < dnp3MinLen+1: // no room for a transport header
		f.Events = append(f.Events, DNP3EventLenTooSmall)
		f.UserData = nil
	case badBlock:
		f.Events = append(f.Events, DNP3EventBadTransportCRC)
		f.UserData = nil
	}
	return f, size, true
}

// DNP3Object is the header of one object block of an application message: the
// group and variation, and the qualifier that says how the points are named
// (range or count) and whether each carries an index or size prefix. Values are
// not decoded.
type DNP3Object struct {
	Group, Variation byte
	Qualifier        byte
	Prefix           byte   // prefix code, qualifier bits 6-4
	Range            byte   // range code, qualifier bits 3-0
	Start, Stop      uint32 // range codes 0-5
	Count            uint32 // number of points, 0 for "all"
	DataLen          int    // bytes of object data that follow, -1 if unknown
}

// DNP3App is a reassembled application fragment.
type DNP3App struct {
	Control      byte
	Function     byte
	FunctionName string
	IIN          uint16 // responses only
	IsResponse   bool
	Objects      []DNP3Object
	// ObjectsComplete is false when decoding the object list stopped early
	// (an object whose size is not known, or a malformed header).
	ObjectsComplete bool
	Events          []string
}

// First, Final, Confirm and Unsolicited are the application control bits.
func (a *DNP3App) First() bool       { return a.Control&0x80 != 0 }
func (a *DNP3App) Final() bool       { return a.Control&0x40 != 0 }
func (a *DNP3App) Confirm() bool     { return a.Control&0x20 != 0 }
func (a *DNP3App) Unsolicited() bool { return a.Control&0x10 != 0 }
func (a *DNP3App) Sequence() byte    { return a.Control & 0x0f }

var dnp3Functions = map[byte]string{
	0: "Confirm", 1: "Read", 2: "Write", 3: "Select", 4: "Operate", 5: "Direct Operate",
	6: "Direct Operate No Ack", 7: "Immediate Freeze", 8: "Immediate Freeze No Ack",
	9: "Freeze and Clear", 10: "Freeze and Clear No Ack", 11: "Freeze at Time",
	12: "Freeze at Time No Ack", 13: "Cold Restart", 14: "Warm Restart",
	15: "Initialize Data", 16: "Initialize Application", 17: "Start Application",
	18: "Stop Application", 19: "Save Configuration", 20: "Enable Unsolicited",
	21: "Disable Unsolicited", 22: "Assign Class", 23: "Delay Measurement",
	24: "Record Current Time", 25: "Open File", 26: "Close File", 27: "Delete File",
	28: "Get File Info", 29: "Authenticate File", 30: "Abort File",
	31: "Activate Configuration", 32: "Authentication Request", 33: "Authentication Error",
	129: "Response", 130: "Unsolicited Response", 131: "Authentication Response",
}

// DNP3FunctionName returns the name of an application function code.
func DNP3FunctionName(fc byte) string { return dnp3Functions[fc] }

// DNP3LinkFunctionName names the link function by its PRM bit and code.
func DNP3LinkFunctionName(primary bool, fc byte) string {
	if primary {
		switch fc {
		case 0:
			return "Reset Link States"
		case 2:
			return "Test Link States"
		case 3:
			return "Confirmed User Data"
		case 4:
			return "Unconfirmed User Data"
		case 9:
			return "Request Link Status"
		}
		return ""
	}
	switch fc {
	case 0:
		return "ACK"
	case 1:
		return "NACK"
	case 11:
		return "Link Status"
	case 15:
		return "Not Supported"
	}
	return ""
}

// dnp3ObjectSize gives the size in bytes of one point of an object, or marks
// the variation as bit-packed (one bit per point). Variable and unlisted
// objects return ok false.
func dnp3ObjectSize(group, variation byte) (size int, packed, ok bool) {
	switch group {
	case 1, 3, 10:
		if variation == 1 {
			return 0, true, true
		}
		if variation == 2 {
			return 1, false, true
		}
	case 80:
		if variation == 1 {
			return 0, true, true
		}
	case 12:
		switch variation {
		case 1, 2:
			return 11, false, true
		case 3:
			return 0, true, true
		}
	case 60:
		if variation >= 1 && variation <= 4 {
			return 0, false, true
		}
	case 110, 111, 112, 113:
		if variation > 0 && variation < 255 {
			return int(variation), false, true
		}
		return 0, false, false
	}
	sizes := map[byte]map[byte]int{
		2:  {1: 1, 2: 7, 3: 3},
		4:  {1: 1, 2: 1, 3: 3},
		11: {1: 1, 2: 7},
		13: {1: 1, 2: 7},
		20: {1: 5, 2: 3, 5: 4, 6: 2, 7: 4, 8: 2},
		21: {1: 5, 2: 3, 5: 11, 6: 9, 9: 4, 10: 2},
		22: {1: 5, 2: 3, 5: 11, 6: 9},
		23: {1: 5, 2: 3, 5: 11, 6: 9},
		30: {1: 5, 2: 3, 3: 4, 4: 2, 5: 5, 6: 9},
		32: {1: 5, 2: 3, 3: 11, 4: 9, 5: 5, 6: 9, 7: 11, 8: 15},
		34: {1: 2, 2: 4, 3: 4},
		40: {1: 5, 2: 3, 3: 5, 4: 9},
		41: {1: 5, 2: 3, 3: 5, 4: 9},
		42: {1: 5, 2: 3, 3: 11, 4: 9, 5: 5, 6: 9, 7: 11, 8: 15},
		50: {1: 6, 3: 6, 4: 10},
		51: {1: 6, 2: 6},
		52: {1: 2, 2: 2},
	}
	if v, found := sizes[group][variation]; found {
		return v, false, true
	}
	return 0, false, false
}

// decodeDNP3App decodes a reassembled fragment (the transport segments
// concatenated, without their transport headers). request says whether the
// fragment comes from the master, which decides whether an IIN field follows
// the function code.
func decodeDNP3App(b []byte, fromMaster bool) *DNP3App {
	a := &DNP3App{}
	if len(b) < 2 {
		a.Events = append(a.Events, DNP3EventMalformed)
		return a
	}
	a.Control, a.Function = b[0], b[1]
	a.FunctionName = dnp3Functions[a.Function]
	a.IsResponse = a.Function >= 129 && a.Function <= 131
	b = b[2:]
	if a.IsResponse {
		if len(b) < 2 {
			a.Events = append(a.Events, DNP3EventMalformed)
			return a
		}
		a.IIN = binary.BigEndian.Uint16(b[:2])
		b = b[2:]
	}
	a.ObjectsComplete = true
	// Read requests and responses to them list objects; most other requests
	// carry data after each header. A read request has no object data.
	hasData := a.Function != 1
	if a.Function == 0 {
		return a
	}
	for len(b) > 0 {
		if len(a.Objects) >= dnp3MaxObjects {
			a.Events = append(a.Events, DNP3EventTooManyObjects)
			a.ObjectsComplete = false
			return a
		}
		o, n, ok := decodeDNP3Object(b, hasData)
		if !ok {
			a.ObjectsComplete = false
			if o.Group != 0 || o.Variation != 0 || o.Qualifier != 0 {
				a.Objects = append(a.Objects, o)
				if o.DataLen < 0 {
					a.Events = append(a.Events, DNP3EventUnknownObject)
					return a
				}
			}
			a.Events = append(a.Events, DNP3EventMalformed)
			return a
		}
		a.Objects = append(a.Objects, o)
		b = b[n:]
	}
	return a
}

// decodeDNP3Object decodes one object header and skips its data. When the
// header parses but the size is unknown the object is returned with DataLen -1
// and ok false.
func decodeDNP3Object(b []byte, hasData bool) (DNP3Object, int, bool) {
	var o DNP3Object
	if len(b) < 3 {
		return o, 0, false
	}
	o.Group, o.Variation, o.Qualifier = b[0], b[1], b[2]
	o.Prefix, o.Range = o.Qualifier>>4&7, o.Qualifier&0x0f
	n := 3
	field := func(w int) (uint32, bool) {
		if len(b) < n+w {
			return 0, false
		}
		var v uint32
		for i := 0; i < w; i++ {
			v |= uint32(b[n+i]) << (8 * i)
		}
		n += w
		return v, true
	}
	var ok bool
	switch o.Range {
	case 0, 3:
		if o.Start, ok = field(1); !ok {
			return o, 0, false
		}
		if o.Stop, ok = field(1); !ok {
			return o, 0, false
		}
	case 1, 4:
		if o.Start, ok = field(2); !ok {
			return o, 0, false
		}
		if o.Stop, ok = field(2); !ok {
			return o, 0, false
		}
	case 2, 5:
		if o.Start, ok = field(4); !ok {
			return o, 0, false
		}
		if o.Stop, ok = field(4); !ok {
			return o, 0, false
		}
	case 6:
	case 7, 0x0b:
		if o.Count, ok = field(1); !ok {
			return o, 0, false
		}
	case 8:
		if o.Count, ok = field(2); !ok {
			return o, 0, false
		}
	case 9:
		if o.Count, ok = field(4); !ok {
			return o, 0, false
		}
	default:
		return o, 0, false
	}
	if o.Range <= 5 {
		if o.Stop < o.Start {
			return o, 0, false
		}
		o.Count = o.Stop - o.Start + 1
	}
	if o.Range == 0x0b || o.Prefix > 6 {
		// Variable format: object sizes follow per object; not walked.
		o.DataLen = -1
		return o, 0, false
	}
	if !hasData || o.Range == 6 {
		return o, n, true
	}
	prefix := [...]int{0, 1, 2, 4, 1, 2, 4}[o.Prefix]
	if o.Prefix >= 4 {
		// Each object starts with its size: walk them.
		total := 0
		for i := uint32(0); i < o.Count; i++ {
			if len(b) < n+total+prefix {
				return o, 0, false
			}
			sz := 0
			for j := 0; j < prefix; j++ {
				sz |= int(b[n+total+j]) << (8 * j)
			}
			total += prefix + sz
			if total > len(b) {
				return o, 0, false
			}
		}
		o.DataLen = total
		if len(b) < n+total {
			return o, 0, false
		}
		return o, n + total, true
	}
	size, packed, known := dnp3ObjectSize(o.Group, o.Variation)
	if !known {
		o.DataLen = -1
		return o, 0, false
	}
	var total uint64
	if packed {
		total = uint64(o.Count+7) / 8
	} else {
		total = uint64(o.Count) * uint64(prefix+size)
	}
	if total > uint64(len(b)-n) {
		o.DataLen = int(min(total, 1<<30))
		return o, 0, false
	}
	o.DataLen = int(total)
	return o, n + int(total), true
}

// DNP3Message is one link frame, with the application fragment it completes
// if it is the last transport segment of one.
type DNP3Message struct {
	Frame        DNP3Frame
	LinkName     string
	HasTransport bool
	FIR, FIN     bool
	TransportSeq byte
	App          *DNP3App
	Events       []string
}
