package detect

import "encoding/binary"

// ModbusAccess classifies what a function code does to the device. It is the
// field a security analysis needs: writes and diagnostics change state.
type ModbusAccess string

const (
	ModbusRead       ModbusAccess = "read"
	ModbusWrite      ModbusAccess = "write"
	ModbusReadWrite  ModbusAccess = "read_write"
	ModbusDiagnostic ModbusAccess = "diagnostic"
	ModbusOther      ModbusAccess = "other"
	ModbusUnknown    ModbusAccess = "unknown"
)

// Anomaly events, named after Suricata's modbus.* events so results compare.
const (
	ModbusEventUnknownFunction  = "unknown_function"
	ModbusEventInvalidException = "invalid_exception_code"
	// ModbusEventInvalidProtocolID: the MBAP protocol id is not 0.
	ModbusEventInvalidProtocolID = "invalid_protocol_id"
	// ModbusEventInvalidFunction: a request carries function code 0 or has the
	// exception bit set. Responses may carry the bit; requests may not.
	ModbusEventInvalidFunction = "invalid_function_code"
	// ModbusEventInvalidLength: the body is shorter or longer than the
	// function allows, or the byte count disagrees with the quantity.
	ModbusEventInvalidLength = "invalid_length"
	// ModbusEventInvalidValue: a quantity, count or value is outside the range
	// the specification allows.
	ModbusEventInvalidValue = "invalid_value"
)

// ModbusMessage is one decoded ADU.
type ModbusMessage struct {
	TransactionID uint16
	UnitID        byte
	FunctionCode  byte // without the exception bit
	RawFunction   byte // as on the wire, exception bit included
	FunctionName  string
	Access        ModbusAccess
	IsException   bool
	ExceptionCode byte
	ExceptionName string
	// Address and Quantity come from the request body; -1 when absent or when
	// the message is a response, whose body layout differs.
	Address  int
	Quantity int
	// WriteAddress and WriteQuantity hold the write range of function 23, whose
	// request carries a read range (Address, Quantity) and a write range.
	WriteAddress  int
	WriteQuantity int
	Events        []string
}

type modbusFunc struct {
	name   string
	access ModbusAccess
	// addrQty: request body starts with a 16-bit address and quantity.
	addrQty bool
	// addrOnly: request body starts with an address, the quantity is 1.
	addrOnly bool
}

// Function codes of the MODBUS Application Protocol V1.1b3, section 6.
var modbusFuncs = map[byte]modbusFunc{
	1:  {"Read Coils", ModbusRead, true, false},
	2:  {"Read Discrete Inputs", ModbusRead, true, false},
	3:  {"Read Holding Registers", ModbusRead, true, false},
	4:  {"Read Input Registers", ModbusRead, true, false},
	5:  {"Write Single Coil", ModbusWrite, false, true},
	6:  {"Write Single Register", ModbusWrite, false, true},
	7:  {"Read Exception Status", ModbusOther, false, false},
	8:  {"Diagnostics", ModbusDiagnostic, false, false},
	11: {"Get Comm Event Counter", ModbusOther, false, false},
	12: {"Get Comm Event Log", ModbusOther, false, false},
	15: {"Write Multiple Coils", ModbusWrite, true, false},
	16: {"Write Multiple Registers", ModbusWrite, true, false},
	17: {"Report Server ID", ModbusOther, false, false},
	20: {"Read File Record", ModbusRead, false, false},
	21: {"Write File Record", ModbusWrite, false, false},
	22: {"Mask Write Register", ModbusWrite, false, true},
	23: {"Read/Write Multiple Registers", ModbusReadWrite, false, false},
	24: {"Read FIFO Queue", ModbusRead, false, false},
	43: {"Encapsulated Interface Transport", ModbusOther, false, false},
}

var modbusExceptions = map[byte]string{
	1:  "Illegal Function",
	2:  "Illegal Data Address",
	3:  "Illegal Data Value",
	4:  "Server Device Failure",
	5:  "Acknowledge",
	6:  "Server Device Busy",
	8:  "Memory Parity Error",
	10: "Gateway Path Unavailable",
	11: "Gateway Target Device Failed to Respond",
}

// isUserDefinedModbusFC reports the ranges the specification reserves for
// user-defined and vendor functions (65-72, 100-110).
func isUserDefinedModbusFC(fc byte) bool {
	return (fc >= 65 && fc <= 72) || (fc >= 100 && fc <= 110)
}

// modbusFrameSize returns the number of bytes the frame at the start of b
// occupies, and whether b holds all of them. It follows sawp-modbus (Suricata):
// a length field outside 2..254 is an error but the frame is still 6+length
// bytes, or everything that is there if that is less, and parsing carries on
// after it. Fewer than the 6 header bytes cannot be judged.
func modbusFrameSize(b []byte) (size int, complete bool) {
	if len(b) < 6 {
		return 0, false
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < 2 || length > 254 {
		size = 6 + length
		if size > len(b) {
			size = len(b)
		}
		return size, true
	}
	return 6 + length, len(b) >= 6+length
}

// DecodeModbusADU decodes the frame at the start of b. request says whether b
// travels client to server: only then is the body read as address and
// quantity, and only then is a function code with the exception bit invalid
// instead of an exception.
//
// Framing is lenient, unlike the probe (ModbusADUSize): a non-zero protocol id
// or a length outside 2..254 is decoded and reported as an event, because the
// caller knows the connection is Modbus. It returns false when b does not yet
// hold the whole frame.
func DecodeModbusADU(b []byte, request bool) (ModbusMessage, bool) {
	size, complete := modbusFrameSize(b)
	if !complete {
		return ModbusMessage{}, false
	}
	b = b[:size]
	m := ModbusMessage{
		TransactionID: binary.BigEndian.Uint16(b[0:2]),
		Access:        ModbusUnknown,
		Address:       -1,
		Quantity:      -1,
		WriteAddress:  -1,
		WriteQuantity: -1,
	}
	if binary.BigEndian.Uint16(b[2:4]) != 0 {
		m.Events = append(m.Events, ModbusEventInvalidProtocolID)
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < 2 || length > 254 {
		m.Events = append(m.Events, ModbusEventInvalidLength)
		return m, true
	}
	m.UnitID = b[6]
	m.RawFunction = b[7]
	fc := b[7]
	body := b[8:size]
	if fc&0x80 != 0 {
		fc &= 0x7f
		if request {
			m.Events = append(m.Events, ModbusEventInvalidFunction)
		} else {
			m.IsException = true
		}
	} else if fc == 0 && request {
		m.Events = append(m.Events, ModbusEventInvalidFunction)
	}
	m.FunctionCode = fc

	f, known := modbusFuncs[fc]
	switch {
	case known:
		m.FunctionName, m.Access = f.name, f.access
	case isUserDefinedModbusFC(fc):
		m.FunctionName = "User Defined"
	case fc == 0:
		m.FunctionName = "Unknown"
	default:
		m.FunctionName = "Unknown"
		m.Events = append(m.Events, ModbusEventUnknownFunction)
	}

	if m.IsException {
		if len(body) >= 1 {
			m.ExceptionCode = body[0]
			name, ok := modbusExceptions[body[0]]
			if ok {
				m.ExceptionName = name
			} else {
				m.Events = append(m.Events, ModbusEventInvalidException)
			}
		}
		return m, true
	}

	if known {
		m.Events = append(m.Events, validateModbusBody(fc, length, body, request)...)
	}

	if request && known {
		switch {
		case f.addrQty && len(body) >= 4:
			m.Address = int(binary.BigEndian.Uint16(body[0:2]))
			m.Quantity = int(binary.BigEndian.Uint16(body[2:4]))
		case fc == 23 && len(body) >= 8:
			m.Address = int(binary.BigEndian.Uint16(body[0:2]))
			m.Quantity = int(binary.BigEndian.Uint16(body[2:4]))
			m.WriteAddress = int(binary.BigEndian.Uint16(body[4:6]))
			m.WriteQuantity = int(binary.BigEndian.Uint16(body[6:8]))
		case f.addrOnly && len(body) >= 2:
			m.Address = int(binary.BigEndian.Uint16(body[0:2]))
			m.Quantity = 1
		}
	}
	return m, true
}

// maxQuantityBits and maxQuantityWords are the limits sawp-modbus (Suricata's
// parser) applies, so our events match Suricata's. The specification lowers
// the limits for some functions (FC16 allows 123 registers); the larger limit
// is the same for both because the 253-byte PDU already caps a write.
const (
	maxQuantityBits  = 2000
	maxQuantityWords = 125
	minReadCount     = 1
	maxReadCount     = 250
)

// validateModbusBody checks a function body against the lengths and ranges the
// specification gives. It returns invalid_length and invalid_value, in that
// order, each at most once. mbapLen is the MBAP length field, which counts the
// unit id and function code besides body.
func validateModbusBody(fc byte, mbapLen int, body []byte, request bool) []string {
	var length, value bool
	if request {
		length, value = validateModbusRequest(fc, mbapLen, body)
	} else {
		length, value = validateModbusResponse(fc, body)
	}
	var ev []string
	if length {
		ev = append(ev, ModbusEventInvalidLength)
	}
	if value {
		ev = append(ev, ModbusEventInvalidValue)
	}
	return ev
}

func isBitAccess(fc byte) bool { return fc == 1 || fc == 2 || fc == 5 || fc == 15 }

func validateModbusRequest(fc byte, mbapLen int, body []byte) (length, value bool) {
	be := binary.BigEndian
	switch fc {
	case 8:
		if len(body) != 4 {
			length = true
		}
		if len(body) == 4 {
			sub, d := be.Uint16(body[0:2]), body[2:4]
			switch {
			case sub == 0 || sub == 4 || (sub > 0x15):
			case sub == 1:
				value = d[1] != 0 || (d[0] != 0 && d[0] != 0xff)
			case sub == 3:
				value = d[1] != 0
			case sub >= 5 && sub <= 9:
			default:
				value = d[0] != 0 || d[1] != 0
			}
		}
		return
	case 43:
		return len(body) < 1, false
	case 20, 21:
		return len(body) == 0, false
	case 7, 11, 12, 17:
		return len(body) > 0, false
	case 24:
		return len(body) != 2, false
	case 1, 2, 3, 4, 23:
		if len(body) < 4 {
			return true, false
		}
		qty := int(be.Uint16(body[2:4]))
		if qty == 0 {
			value = true
		}
		if fc != 23 && len(body) > 4 {
			length = true
		}
		if isBitAccess(fc) {
			value = value || qty > maxQuantityBits
		} else {
			value = value || qty > maxQuantityWords
		}
		if fc == 23 {
			l, v := validateModbusMultipleWrite(fc, mbapLen, body[4:])
			return length || l, value || v
		}
		return
	case 5, 6:
		if len(body) < 4 {
			return true, false
		}
		if len(body) > 4 {
			length = true
		}
		if fc == 5 {
			if v := be.Uint16(body[2:4]); v != 0 && v != 0xff00 {
				value = true
			}
		}
		return
	case 22:
		return len(body) != 6, false
	case 15, 16:
		return validateModbusMultipleWrite(fc, mbapLen, body)
	}
	return false, false
}

// validateModbusMultipleWrite checks address, quantity, byte count, data.
// For FC23 body starts at the write part, after the 4-byte read range.
func validateModbusMultipleWrite(fc byte, mbapLen int, body []byte) (length, value bool) {
	if len(body) < 5 {
		return true, false
	}
	qty, count := int(binary.BigEndian.Uint16(body[2:4])), int(body[4])
	offset := 7
	if fc == 23 {
		offset += 4
	}
	if qty == 0 || mbapLen-offset != count {
		length = true
	}
	if isBitAccess(fc) {
		value = qty > maxQuantityBits || count != (qty+7)/8
	} else {
		value = qty > maxQuantityWords || count != 2*qty
	}
	return
}

func validateModbusResponse(fc byte, body []byte) (length, value bool) {
	be := binary.BigEndian
	switch fc {
	case 7:
		return len(body) != 1, false
	case 11:
		return len(body) != 4, false
	case 8:
		return len(body) < 2, false
	case 43:
		return len(body) < 1, false
	case 1, 2, 3, 4, 23:
		if len(body) < 1 {
			return true, false
		}
		count := int(body[0])
		return false, count < minReadCount || count > maxReadCount || len(body)-1 != count
	case 5, 6:
		return len(body) != 4, false
	case 15, 16:
		if len(body) != 4 {
			return true, false
		}
		return false, be.Uint16(body[2:4]) == 0
	case 22:
		return len(body) != 6, false
	}
	return false, false
}
