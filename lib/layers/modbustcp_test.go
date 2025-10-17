package lib_layers

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
)

// Test ModbusProtocol String method
func TestModbusProtocol_String(t *testing.T) {
	tests := []struct {
		name     string
		protocol ModbusProtocol
		expected string
	}{
		{
			name:     "Modbus protocol",
			protocol: ModbusProtocolModbus,
			expected: "Modbus",
		},
		{
			name:     "Unknown protocol",
			protocol: ModbusProtocol(999),
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.protocol.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test successful ModbusTCP decoding
func TestModbusTCP_DecodeFromBytes_Success(t *testing.T) {
	// Create a valid ModbusTCP packet
	// MBAP Header (7 bytes) + minimal PDU (2 bytes: function code + data)
	data := make([]byte, 9)

	// Transaction Identifier (2 bytes)
	binary.BigEndian.PutUint16(data[0:2], 0x0001)
	// Protocol Identifier (2 bytes) - 0x0000 for Modbus
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	// Length (2 bytes) - number of following bytes (1 byte unit ID + 2 bytes PDU = 3)
	binary.BigEndian.PutUint16(data[4:6], 0x0003)
	// Unit Identifier (1 byte)
	data[6] = 0x01
	// PDU: Function Code (1 byte) + Data (1 byte)
	data[7] = 0x03 // Read Holding Registers
	data[8] = 0x00 // Minimal data

	// Create ModbusTCP instance and decode
	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.NoError(t, err)
	assert.Equal(t, uint16(0x0001), modbus.TransactionIdentifier)
	assert.Equal(t, ModbusProtocolModbus, modbus.ProtocolIdentifier)
	assert.Equal(t, uint16(0x0003), modbus.Length)
	assert.Equal(t, uint8(0x01), modbus.UnitIdentifier)
	assert.Equal(t, data[:7], modbus.Contents)
	assert.Equal(t, data[7:], modbus.Payload())
	assert.False(t, df.truncated)
}

// Test ModbusTCP packet too short
func TestModbusTCP_DecodeFromBytes_TooShort(t *testing.T) {
	// Create packet shorter than minimum size (7 MBAP + 2 PDU = 9 bytes)
	data := make([]byte, 8)

	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
	assert.True(t, df.truncated)
}

// Test ModbusTCP packet too long
func TestModbusTCP_DecodeFromBytes_TooLong(t *testing.T) {
	// Create packet longer than maximum size (7 MBAP + 253 PDU = 260 bytes)
	data := make([]byte, 261)

	// Fill MBAP header
	binary.BigEndian.PutUint16(data[0:2], 0x0001)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	binary.BigEndian.PutUint16(data[4:6], 0x00FE) // 254 bytes following
	data[6] = 0x01

	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
	assert.True(t, df.truncated)
}

// Test ModbusTCP with wrong Length field
func TestModbusTCP_DecodeFromBytes_WrongLength(t *testing.T) {
	// Create a valid packet structure but with incorrect Length field
	data := make([]byte, 9)

	binary.BigEndian.PutUint16(data[0:2], 0x0001)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	// Length field says 10 bytes follow, but only 2 bytes (PDU) actually follow
	binary.BigEndian.PutUint16(data[4:6], 0x000A)
	data[6] = 0x01
	data[7] = 0x03
	data[8] = 0x00

	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wrong field value")
	assert.True(t, df.truncated)
}

// Test ModbusTCP with maximum valid PDU size
func TestModbusTCP_DecodeFromBytes_MaxPDU(t *testing.T) {
	// Create packet with maximum PDU size (253 bytes)
	data := make([]byte, 7+253)

	binary.BigEndian.PutUint16(data[0:2], 0xFFFF)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	binary.BigEndian.PutUint16(data[4:6], 254) // 1 unit ID + 253 PDU
	data[6] = 0xFF
	// Fill PDU with test data
	for i := 7; i < len(data); i++ {
		data[i] = byte(i % 256)
	}

	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.NoError(t, err)
	assert.Equal(t, uint16(0xFFFF), modbus.TransactionIdentifier)
	assert.Equal(t, uint8(0xFF), modbus.UnitIdentifier)
	assert.Len(t, modbus.Payload(), 253)
	assert.False(t, df.truncated)
}

// Test ModbusTCP with minimum valid PDU size
func TestModbusTCP_DecodeFromBytes_MinPDU(t *testing.T) {
	// Create packet with minimum PDU size (2 bytes)
	data := make([]byte, 9)

	binary.BigEndian.PutUint16(data[0:2], 0x0000)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	binary.BigEndian.PutUint16(data[4:6], 3) // 1 unit ID + 2 PDU
	data[6] = 0x00
	data[7] = 0x01
	data[8] = 0x00

	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.NoError(t, err)
	assert.Len(t, modbus.Payload(), 2)
	assert.False(t, df.truncated)
}

// Test LayerType method
func TestModbusTCP_LayerType(t *testing.T) {
	modbus := &ModbusTCP{}
	layerType := modbus.LayerType()

	assert.NotNil(t, layerType)
	assert.Equal(t, "ModbusTCP", layerType.String())
}

// Test NextLayerType method
func TestModbusTCP_NextLayerType(t *testing.T) {
	modbus := &ModbusTCP{}
	nextLayer := modbus.NextLayerType()

	assert.Equal(t, gopacket.LayerTypePayload, nextLayer)
}

// Test Payload method
func TestModbusTCP_Payload(t *testing.T) {
	data := make([]byte, 10)

	binary.BigEndian.PutUint16(data[0:2], 0x0001)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	binary.BigEndian.PutUint16(data[4:6], 4) // 1 unit ID + 3 PDU
	data[6] = 0x01
	data[7] = 0x03
	data[8] = 0xAB
	data[9] = 0xCD

	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.NoError(t, err)
	payload := modbus.Payload()
	assert.Equal(t, []byte{0x03, 0xAB, 0xCD}, payload)
}

// Test CanDecode method
func TestModbusTCP_CanDecode(t *testing.T) {
	modbus := &ModbusTCP{}
	layerClass := modbus.CanDecode()

	assert.NotNil(t, layerClass)
}

// Test decodeModbusTCP function
func TestDecodeModbusTCP(t *testing.T) {
	data := make([]byte, 9)

	binary.BigEndian.PutUint16(data[0:2], 0x1234)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	binary.BigEndian.PutUint16(data[4:6], 3)
	data[6] = 0x11
	data[7] = 0x10
	data[8] = 0x20

	pb := gopacket.NewPacket(data, LayerTypeModbusTCP, gopacket.Default)

	// Check that the packet was decoded
	assert.NotNil(t, pb)

	// Check for ModbusTCP layer
	modbusLayer := pb.Layer(LayerTypeModbusTCP)
	if modbusLayer != nil {
		modbus, ok := modbusLayer.(*ModbusTCP)
		assert.True(t, ok)
		assert.Equal(t, uint16(0x1234), modbus.TransactionIdentifier)
	}
}

// Test with different protocol identifiers
func TestModbusTCP_DecodeFromBytes_DifferentProtocols(t *testing.T) {
	tests := []struct {
		name       string
		protocolID uint16
		expected   ModbusProtocol
	}{
		{
			name:       "Standard Modbus",
			protocolID: 0x0000,
			expected:   ModbusProtocolModbus,
		},
		{
			name:       "Unknown protocol",
			protocolID: 0x0001,
			expected:   ModbusProtocol(0x0001),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 9)

			binary.BigEndian.PutUint16(data[0:2], 0x0001)
			binary.BigEndian.PutUint16(data[2:4], tt.protocolID)
			binary.BigEndian.PutUint16(data[4:6], 3)
			data[6] = 0x01
			data[7] = 0x03
			data[8] = 0x00

			modbus := &ModbusTCP{}
			df := &testDecodeFeedback{}
			err := modbus.DecodeFromBytes(data, df)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, modbus.ProtocolIdentifier)
		})
	}
}

// Test edge case with exact minimum size
func TestModbusTCP_DecodeFromBytes_ExactMinimum(t *testing.T) {
	// Exactly 9 bytes: 7 MBAP + 2 PDU
	data := make([]byte, 9)

	binary.BigEndian.PutUint16(data[0:2], 0x0001)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	binary.BigEndian.PutUint16(data[4:6], 3)
	data[6] = 0x01
	data[7] = 0x04
	data[8] = 0x01

	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.NoError(t, err)
	assert.Len(t, modbus.Contents, 7)
	assert.Len(t, modbus.Payload(), 2)
}

// Test edge case with exact maximum size
func TestModbusTCP_DecodeFromBytes_ExactMaximum(t *testing.T) {
	// Exactly 260 bytes: 7 MBAP + 253 PDU
	data := make([]byte, 260)

	binary.BigEndian.PutUint16(data[0:2], 0x0001)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	binary.BigEndian.PutUint16(data[4:6], 254) // 1 + 253
	data[6] = 0x01

	modbus := &ModbusTCP{}
	df := &testDecodeFeedback{}
	err := modbus.DecodeFromBytes(data, df)

	assert.NoError(t, err)
	assert.Len(t, modbus.Payload(), 253)
}

// Test with various function codes in PDU
func TestModbusTCP_DecodeFromBytes_VariousFunctionCodes(t *testing.T) {
	functionCodes := []byte{
		0x01, // Read Coils
		0x02, // Read Discrete Inputs
		0x03, // Read Holding Registers
		0x04, // Read Input Registers
		0x05, // Write Single Coil
		0x06, // Write Single Register
		0x0F, // Write Multiple Coils
		0x10, // Write Multiple Registers
	}

	for _, fc := range functionCodes {
		t.Run("Function code "+string(fc), func(t *testing.T) {
			data := make([]byte, 10)

			binary.BigEndian.PutUint16(data[0:2], 0x0001)
			binary.BigEndian.PutUint16(data[2:4], 0x0000)
			binary.BigEndian.PutUint16(data[4:6], 4)
			data[6] = 0x01
			data[7] = fc
			data[8] = 0x00
			data[9] = 0x00

			modbus := &ModbusTCP{}
			df := &testDecodeFeedback{}
			err := modbus.DecodeFromBytes(data, df)

			assert.NoError(t, err)
			assert.Equal(t, fc, modbus.Payload()[0], "Function code should be preserved in payload")
		})
	}
}

// Helper type for testing DecodeFeedback
type testDecodeFeedback struct {
	truncated bool
}

func (t *testDecodeFeedback) SetTruncated() {
	t.truncated = true
}
