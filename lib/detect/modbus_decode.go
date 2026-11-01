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
)

// ModbusMessage is one decoded ADU.
type ModbusMessage struct {
	TransactionID uint16
	UnitID        byte
	FunctionCode  byte // without the exception bit
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

// DecodeModbusADU decodes the ADU at the start of b. request says whether b
// travels client to server: only then is the body read as address and quantity.
// It returns false when b does not start with a valid MBAP header.
func DecodeModbusADU(b []byte, request bool) (ModbusMessage, bool) {
	size, ok := ModbusADUSize(b)
	if !ok || size > len(b) {
		return ModbusMessage{}, false
	}
	m := ModbusMessage{
		TransactionID: binary.BigEndian.Uint16(b[0:2]),
		UnitID:        b[6],
		Address:       -1,
		Quantity:      -1,
		WriteAddress:  -1,
		WriteQuantity: -1,
	}
	fc := b[7]
	body := b[8:size]
	if fc&0x80 != 0 {
		m.IsException = true
		fc &= 0x7f
	}
	m.FunctionCode = fc

	f, known := modbusFuncs[fc]
	switch {
	case known:
		m.FunctionName, m.Access = f.name, f.access
	case isUserDefinedModbusFC(fc):
		m.FunctionName, m.Access = "User Defined", ModbusUnknown
	default:
		m.FunctionName, m.Access = "Unknown", ModbusUnknown
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
