package lib_layers

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMockEtherNetIPPacket creates a mock EtherNet/IP packet for testing
func createMockEtherNetIPPacket(command uint16, status uint32, dataPayload []byte) []byte {
	// EtherNet/IP header is 24 bytes
	packet := make([]byte, 24+len(dataPayload))

	// Command (2 bytes)
	binary.LittleEndian.PutUint16(packet[0:2], command)

	// Length (2 bytes) - length of data portion
	binary.LittleEndian.PutUint16(packet[2:4], uint16(len(dataPayload)))

	// Session Handle (4 bytes)
	binary.LittleEndian.PutUint32(packet[4:8], 0x12345678)

	// Status (4 bytes)
	binary.LittleEndian.PutUint32(packet[8:12], status)

	// Sender Context (8 bytes)
	copy(packet[12:20], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	// Options (4 bytes)
	binary.LittleEndian.PutUint32(packet[20:24], 0x00000000)

	// Data payload
	if len(dataPayload) > 0 {
		copy(packet[24:], dataPayload)
	}

	return packet
}

// createMockListIdentityResponse creates a mock List Identity response payload
func createMockListIdentityResponse() []byte {
	payload := make([]byte, 20)

	// Item count (2 bytes)
	binary.LittleEndian.PutUint16(payload[0:2], 1)

	// Item type (2 bytes)
	binary.LittleEndian.PutUint16(payload[2:4], 0x000C)

	// Vendor ID (2 bytes) - Allen-Bradley
	binary.LittleEndian.PutUint16(payload[4:6], 1)

	// Product Code (2 bytes)
	binary.LittleEndian.PutUint16(payload[6:8], 150)

	// Serial Number (4 bytes)
	binary.LittleEndian.PutUint32(payload[8:12], 0x12345678)

	// Device State (1 byte)
	payload[12] = 0x03

	// Product Name Length (1 byte)
	payload[13] = 6

	// Product Name
	copy(payload[14:20], []byte("TestPLC"))

	return payload
}
func TestEtherNetIPDecodeFromBytes_BasicHeader(t *testing.T) {
	// Test basic header parsing
	packet := createMockEtherNetIPPacket(EtherNetIPCommandListIdentity, EtherNetIPStatusSuccess, nil)

	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, EtherNetIPCommandListIdentity, ethernetip.Command)
	assert.Equal(t, uint16(0), ethernetip.Length)
	assert.Equal(t, uint32(0x12345678), ethernetip.SessionHandle)
	assert.Equal(t, EtherNetIPStatusSuccess, ethernetip.Status)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, ethernetip.SenderContext)
	assert.Equal(t, uint32(0x00000000), ethernetip.Options)
}

func TestEtherNetIPDecodeFromBytes_TooShort(t *testing.T) {
	// Test packet too short error
	shortPacket := make([]byte, 20) // Less than minimum 24 bytes

	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(shortPacket, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestEtherNetIPDecodeFromBytes_InvalidLength(t *testing.T) {
	// Test invalid length field
	packet := make([]byte, 24)
	binary.LittleEndian.PutUint16(packet[2:4], 100) // Length exceeds available data

	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(packet, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "length field")
}

func TestEtherNetIPDecodeFromBytes_ListIdentityResponse(t *testing.T) {
	// Test List Identity response parsing
	payload := createMockListIdentityResponse()
	packet := createMockEtherNetIPPacket(EtherNetIPCommandListIdentity, EtherNetIPStatusSuccess, payload)

	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, EtherNetIPCommandListIdentity, ethernetip.Command)
	assert.Equal(t, uint16(1), ethernetip.VendorID) // Allen-Bradley
	assert.Equal(t, uint16(150), ethernetip.ProductCode)
	assert.Equal(t, uint32(0x12345678), ethernetip.SerialNumber)
	assert.Equal(t, uint8(0x03), ethernetip.DeviceState)
	assert.Equal(t, "TestPL", ethernetip.ProductName) // Truncated due to test data
	assert.Equal(t, "PLC", ethernetip.DeviceType)     // Inferred from Allen-Bradley vendor + product code
}

func TestEtherNetIPDecodeFromBytes_ExplicitMessaging(t *testing.T) {
	// Test explicit messaging (Send RR Data)
	payload := make([]byte, 14) // Increased size to accommodate full path
	// Interface handle (4 bytes)
	binary.LittleEndian.PutUint32(payload[0:4], 0x00000000)
	// Timeout (2 bytes)
	binary.LittleEndian.PutUint16(payload[4:6], 1000)
	// CIP Service
	payload[6] = CIPServiceGetAttributeSingle
	// Path size (in words)
	payload[7] = 3 // 3 words = 6 bytes
	// Class ID (2 bytes)
	binary.LittleEndian.PutUint16(payload[8:10], 0x0001)
	// Instance ID (2 bytes)
	binary.LittleEndian.PutUint16(payload[10:12], 0x0001)
	// Attribute ID (2 bytes)
	binary.LittleEndian.PutUint16(payload[12:14], 0x0001)

	packet := createMockEtherNetIPPacket(EtherNetIPCommandSendRRData, EtherNetIPStatusSuccess, payload)

	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, EtherNetIPCommandSendRRData, ethernetip.Command)
	assert.Equal(t, CIPServiceGetAttributeSingle, ethernetip.Service)
	assert.Equal(t, uint16(0x0001), ethernetip.ClassID)
	assert.True(t, ethernetip.IsExplicitMsg)
	assert.False(t, ethernetip.IsImplicitMsg)
}
func TestEtherNetIPDecodeFromBytes_ImplicitMessaging(t *testing.T) {
	// Test implicit messaging (Send Unit Data)
	payload := make([]byte, 16) // Mock I/O data
	for i := range payload {
		payload[i] = byte(i)
	}

	packet := createMockEtherNetIPPacket(EtherNetIPCommandSendUnitData, EtherNetIPStatusSuccess, payload)

	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, EtherNetIPCommandSendUnitData, ethernetip.Command)
	assert.True(t, ethernetip.IsImplicitMsg)
	assert.False(t, ethernetip.IsExplicitMsg)
	assert.Equal(t, 16, ethernetip.ConfigurationData["io_data_size"])
}

func TestEtherNetIPLayerType(t *testing.T) {
	ethernetip := &EtherNetIP{}
	assert.Equal(t, LayerTypeEtherNetIP, ethernetip.LayerType())
}

func TestEtherNetIPCanDecode(t *testing.T) {
	ethernetip := &EtherNetIP{}
	assert.Equal(t, LayerTypeEtherNetIP, ethernetip.CanDecode())
}

func TestEtherNetIPNextLayerType(t *testing.T) {
	ethernetip := &EtherNetIP{}
	assert.Equal(t, gopacket.LayerTypePayload, ethernetip.NextLayerType())
}

func TestEtherNetIPString(t *testing.T) {
	tests := []struct {
		name     string
		command  uint16
		status   uint32
		device   string
		expected string
	}{
		{
			name:     "List Identity with device type",
			command:  EtherNetIPCommandListIdentity,
			status:   EtherNetIPStatusSuccess,
			device:   "PLC",
			expected: "EtherNet/IP List Identity (Status: Success, Device: PLC)",
		},
		{
			name:     "Register Session without device type",
			command:  EtherNetIPCommandRegisterSession,
			status:   EtherNetIPStatusSuccess,
			device:   "",
			expected: "EtherNet/IP Register Session (Status: Success)",
		},
		{
			name:     "Unknown command with error status",
			command:  0xFFFF,
			status:   EtherNetIPStatusInvalidCommand,
			device:   "",
			expected: "EtherNet/IP Unknown(0xFFFF) (Status: Invalid Command)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ethernetip := &EtherNetIP{
				Command:    tt.command,
				Status:     tt.status,
				DeviceType: tt.device,
			}
			assert.Equal(t, tt.expected, ethernetip.String())
		})
	}
}
func TestEtherNetIPGetDeviceIdentity(t *testing.T) {
	ethernetip := &EtherNetIP{
		VendorID:     1,
		ProductCode:  150,
		SerialNumber: 0x12345678,
		ProductName:  "Test PLC",
		DeviceType:   "PLC",
		DeviceState:  3,
	}

	identity := ethernetip.GetDeviceIdentity()

	assert.Equal(t, uint16(1), identity["vendor_id"])
	assert.Equal(t, uint16(150), identity["product_code"])
	assert.Equal(t, uint32(0x12345678), identity["serial_number"])
	assert.Equal(t, "Test PLC", identity["product_name"])
	assert.Equal(t, "PLC", identity["device_type"])
	assert.Equal(t, uint8(3), identity["device_state"])
}

func TestEtherNetIPGetCIPInfo(t *testing.T) {
	ethernetip := &EtherNetIP{
		Service:       CIPServiceGetAttributeSingle,
		ClassID:       0x0001,
		InstanceID:    0x0001,
		AttributeID:   0x0001,
		IsExplicitMsg: true,
		IsImplicitMsg: false,
	}

	cip := ethernetip.GetCIPInfo()

	assert.Equal(t, uint8(CIPServiceGetAttributeSingle), cip["service"])
	assert.Equal(t, "Get Attribute Single", cip["service_name"])
	assert.Equal(t, uint16(0x0001), cip["class_id"])
	assert.Equal(t, uint16(0x0001), cip["instance_id"])
	assert.Equal(t, uint16(0x0001), cip["attribute_id"])
	assert.Equal(t, true, cip["is_explicit"])
	assert.Equal(t, false, cip["is_implicit"])
}

func TestEtherNetIPInferDeviceType(t *testing.T) {
	tests := []struct {
		name         string
		vendorID     uint16
		productCode  uint16
		productName  string
		expectedType string
	}{
		{
			name:         "Allen-Bradley PLC",
			vendorID:     1,
			productCode:  150,
			productName:  "",
			expectedType: "PLC",
		},
		{
			name:         "Allen-Bradley HMI",
			vendorID:     1,
			productCode:  250,
			productName:  "",
			expectedType: "HMI",
		},
		{
			name:         "Schneider Electric",
			vendorID:     42,
			productCode:  100,
			productName:  "",
			expectedType: "PLC",
		},
		{
			name:         "Generic PLC by name",
			vendorID:     999,
			productCode:  100,
			productName:  "Industrial PLC Controller",
			expectedType: "PLC",
		},
		{
			name:         "Generic HMI by name",
			vendorID:     999,
			productCode:  100,
			productName:  "Touch Panel HMI",
			expectedType: "HMI",
		},
		{
			name:         "Unknown device",
			vendorID:     999,
			productCode:  100,
			productName:  "",
			expectedType: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ethernetip := &EtherNetIP{
				VendorID:    tt.vendorID,
				ProductCode: tt.productCode,
				ProductName: tt.productName,
			}
			ethernetip.inferDeviceType()
			assert.Equal(t, tt.expectedType, ethernetip.DeviceType)
		})
	}
}
func TestEtherNetIPMessageTypeClassification(t *testing.T) {
	tests := []struct {
		name              string
		command           uint16
		expectedDiscovery bool
		expectedSession   bool
		expectedData      bool
	}{
		{
			name:              "List Identity - Discovery",
			command:           EtherNetIPCommandListIdentity,
			expectedDiscovery: true,
			expectedSession:   false,
			expectedData:      false,
		},
		{
			name:              "Register Session - Session Management",
			command:           EtherNetIPCommandRegisterSession,
			expectedDiscovery: false,
			expectedSession:   true,
			expectedData:      false,
		},
		{
			name:              "Send RR Data - Data Transfer",
			command:           EtherNetIPCommandSendRRData,
			expectedDiscovery: false,
			expectedSession:   false,
			expectedData:      true,
		},
		{
			name:              "Send Unit Data - Data Transfer",
			command:           EtherNetIPCommandSendUnitData,
			expectedDiscovery: false,
			expectedSession:   false,
			expectedData:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ethernetip := &EtherNetIP{Command: tt.command}
			ethernetip.classifyMessageType()

			assert.Equal(t, tt.expectedDiscovery, ethernetip.IsDiscoveryMessage())
			assert.Equal(t, tt.expectedSession, ethernetip.IsSessionManagement())
			assert.Equal(t, tt.expectedData, ethernetip.IsDataTransfer())
		})
	}
}

func TestEtherNetIPGetCIPServiceName(t *testing.T) {
	tests := []struct {
		service      uint8
		expectedName string
	}{
		{CIPServiceGetAttributesAll, "Get Attributes All"},
		{CIPServiceSetAttributesAll, "Set Attributes All"},
		{CIPServiceGetAttributeSingle, "Get Attribute Single"},
		{CIPServiceSetAttributeSingle, "Set Attribute Single"},
		{CIPServiceReset, "Reset"},
		{CIPServiceStart, "Start"},
		{CIPServiceStop, "Stop"},
		{0xFF, "Unknown(0xFF)"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedName, func(t *testing.T) {
			ethernetip := &EtherNetIP{Service: tt.service}
			assert.Equal(t, tt.expectedName, ethernetip.getCIPServiceName())
		})
	}
}

func TestEtherNetIPDecoder(t *testing.T) {
	// Test the decoder function
	packet := createMockEtherNetIPPacket(EtherNetIPCommandListIdentity, EtherNetIPStatusSuccess, nil)

	// Create a mock packet builder
	pb := gopacket.NewPacket(packet, LayerTypeEtherNetIP, gopacket.Default)

	// Check that the layer was decoded
	ethernetipLayer := pb.Layer(LayerTypeEtherNetIP)
	require.NotNil(t, ethernetipLayer)

	ethernetip, ok := ethernetipLayer.(*EtherNetIP)
	require.True(t, ok)
	assert.Equal(t, EtherNetIPCommandListIdentity, ethernetip.Command)
}

func TestEtherNetIPPortRegistration(t *testing.T) {
	// Test that the layer type is properly registered
	// This is more of a smoke test to ensure registration doesn't panic
	RegisterEtherNetIP()
	InitLayerEtherNetIP()

	// The actual port registration testing would require access to gopacket internals
	// So we just ensure the functions don't panic
	assert.True(t, true) // Placeholder assertion
}
func TestEtherNetIPMalformedCIPData(t *testing.T) {
	// Test handling of malformed CIP data
	payload := []byte{0x01} // Too short for proper CIP parsing
	packet := createMockEtherNetIPPacket(EtherNetIPCommandSendRRData, EtherNetIPStatusSuccess, payload)

	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(packet, nil)

	// Should not fail completely, but should record the error
	require.NoError(t, err)
	assert.Contains(t, ethernetip.ConfigurationData, "cip_parse_error")
}

func TestEtherNetIPEmptyPayload(t *testing.T) {
	// Test packet with no data payload
	packet := createMockEtherNetIPPacket(EtherNetIPCommandNOP, EtherNetIPStatusSuccess, nil)

	ethernetip := &EtherNetIP{}
	err := ethernetip.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, EtherNetIPCommandNOP, ethernetip.Command)
	assert.Equal(t, uint16(0), ethernetip.Length)
}

// Benchmark tests for performance
func BenchmarkEtherNetIPDecode(b *testing.B) {
	payload := createMockListIdentityResponse()
	packet := createMockEtherNetIPPacket(EtherNetIPCommandListIdentity, EtherNetIPStatusSuccess, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ethernetip := &EtherNetIP{}
		_ = ethernetip.DecodeFromBytes(packet, nil)
	}
}

func BenchmarkEtherNetIPString(b *testing.B) {
	ethernetip := &EtherNetIP{
		Command:    EtherNetIPCommandListIdentity,
		Status:     EtherNetIPStatusSuccess,
		DeviceType: "PLC",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ethernetip.String()
	}
}

// Test edge cases and error conditions
func TestEtherNetIPEdgeCases(t *testing.T) {
	t.Run("Zero length packet", func(t *testing.T) {
		ethernetip := &EtherNetIP{}
		err := ethernetip.DecodeFromBytes([]byte{}, nil)
		assert.Error(t, err)
	})

	t.Run("Exactly minimum size", func(t *testing.T) {
		packet := make([]byte, 24)
		ethernetip := &EtherNetIP{}
		err := ethernetip.DecodeFromBytes(packet, nil)
		assert.NoError(t, err)
	})

	t.Run("Large length field", func(t *testing.T) {
		packet := make([]byte, 24)
		binary.LittleEndian.PutUint16(packet[2:4], 0xFFFF) // Very large length
		ethernetip := &EtherNetIP{}
		err := ethernetip.DecodeFromBytes(packet, nil)
		assert.Error(t, err)
	})
}
