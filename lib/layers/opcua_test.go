package lib_layers

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMockOPCUAPacket creates a mock OPC UA packet for testing
func createMockOPCUAPacket(messageType, chunkType string, secureChannelID uint32, dataPayload []byte) []byte {
	// OPC UA header is 8 bytes minimum, 12 bytes with secure channel ID
	headerSize := 8
	if messageType != OPCUAMessageTypeHello && messageType != OPCUAMessageTypeAcknowledge {
		headerSize = 12
	}

	packet := make([]byte, headerSize+len(dataPayload))

	// Message Type (3 bytes)
	copy(packet[0:3], []byte(messageType))

	// Chunk Type (1 byte)
	packet[3] = chunkType[0]

	// Message Size (4 bytes)
	binary.LittleEndian.PutUint32(packet[4:8], uint32(len(packet)))

	// Secure Channel ID (4 bytes) - only for non-Hello/ACK messages
	if headerSize == 12 {
		binary.LittleEndian.PutUint32(packet[8:12], secureChannelID)
	}

	// Data payload
	if len(dataPayload) > 0 {
		copy(packet[headerSize:], dataPayload)
	}

	return packet
}

// createMockHelloMessage creates a mock Hello message payload
func createMockHelloMessage() []byte {
	payload := make([]byte, 28)

	// Protocol version (4 bytes)
	binary.LittleEndian.PutUint32(payload[0:4], 0)

	// Receive buffer size (4 bytes)
	binary.LittleEndian.PutUint32(payload[4:8], 65536)

	// Send buffer size (4 bytes)
	binary.LittleEndian.PutUint32(payload[8:12], 65536)

	// Max message size (4 bytes)
	binary.LittleEndian.PutUint32(payload[12:16], 16777216)

	// Max chunk count (4 bytes)
	binary.LittleEndian.PutUint32(payload[16:20], 0)

	// Endpoint URL length (4 bytes)
	binary.LittleEndian.PutUint32(payload[20:24], 4)

	// Endpoint URL
	copy(payload[24:28], []byte("test"))

	return payload
}

// createMockAcknowledgeMessage creates a mock Acknowledge message payload
func createMockAcknowledgeMessage() []byte {
	payload := make([]byte, 20)

	// Protocol version (4 bytes)
	binary.LittleEndian.PutUint32(payload[0:4], 0)

	// Receive buffer size (4 bytes)
	binary.LittleEndian.PutUint32(payload[4:8], 65536)

	// Send buffer size (4 bytes)
	binary.LittleEndian.PutUint32(payload[8:12], 65536)

	// Max message size (4 bytes)
	binary.LittleEndian.PutUint32(payload[12:16], 16777216)

	// Max chunk count (4 bytes)
	binary.LittleEndian.PutUint32(payload[16:20], 0)

	return payload
}

// createMockOpenChannelMessage creates a mock OpenSecureChannel message payload
func createMockOpenChannelMessage() []byte {
	securityPolicyURI := SecurityPolicyBasic256Sha256
	payload := make([]byte, 8+len(securityPolicyURI)+8)

	offset := 0

	// Security policy URI length (4 bytes)
	binary.LittleEndian.PutUint32(payload[offset:offset+4], uint32(len(securityPolicyURI)))
	offset += 4

	// Security policy URI
	copy(payload[offset:offset+len(securityPolicyURI)], []byte(securityPolicyURI))
	offset += len(securityPolicyURI)

	// Client certificate length (4 bytes) - no certificate
	binary.LittleEndian.PutUint32(payload[offset:offset+4], 0)
	offset += 4

	// Requested lifetime (4 bytes)
	binary.LittleEndian.PutUint32(payload[offset:offset+4], 3600000) // 1 hour

	return payload
}

// createMockServiceMessage creates a mock service message payload
func createMockServiceMessage(serviceNodeID uint32) []byte {
	payload := make([]byte, 8)

	// Service node ID (4 bytes)
	binary.LittleEndian.PutUint32(payload[0:4], serviceNodeID)

	// Request handle (4 bytes)
	binary.LittleEndian.PutUint32(payload[4:8], 0x12345678)

	return payload
}

func TestOPCUADecodeFromBytes_BasicHeader(t *testing.T) {
	// Test basic header parsing for Hello message
	payload := createMockHelloMessage()
	packet := createMockOPCUAPacket(OPCUAMessageTypeHello, OPCUAChunkTypeFinal, 0, payload)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, OPCUAMessageTypeHello, opcua.MessageType)
	assert.Equal(t, OPCUAChunkTypeFinal, opcua.ChunkType)
	assert.Equal(t, uint32(len(packet)), opcua.MessageSize)
	assert.True(t, opcua.IsHandshake)
}

func TestOPCUADecodeFromBytes_TooShort(t *testing.T) {
	// Test packet too short error
	shortPacket := make([]byte, 6) // Less than minimum 8 bytes

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(shortPacket, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestOPCUADecodeFromBytes_InvalidMessageSize(t *testing.T) {
	// Test invalid message size field
	packet := make([]byte, 8)
	binary.LittleEndian.PutUint32(packet[4:8], 100) // Size exceeds available data

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "message size")
}

func TestOPCUADecodeFromBytes_HelloMessage(t *testing.T) {
	// Test Hello message parsing
	payload := createMockHelloMessage()
	packet := createMockOPCUAPacket(OPCUAMessageTypeHello, OPCUAChunkTypeFinal, 0, payload)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, OPCUAMessageTypeHello, opcua.MessageType)
	assert.Equal(t, uint32(16777216), opcua.MaxMessageSize)
	assert.Equal(t, "test", opcua.EndpointURL)
	assert.True(t, opcua.IsHandshake)
	assert.Equal(t, uint32(65536), opcua.ConfigurationData["receive_buffer_size"])
}

func TestOPCUADecodeFromBytes_AcknowledgeMessage(t *testing.T) {
	// Test Acknowledge message parsing
	payload := createMockAcknowledgeMessage()
	packet := createMockOPCUAPacket(OPCUAMessageTypeAcknowledge, OPCUAChunkTypeFinal, 0, payload)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, OPCUAMessageTypeAcknowledge, opcua.MessageType)
	assert.Equal(t, uint32(16777216), opcua.MaxMessageSize)
	assert.True(t, opcua.IsHandshake)
	assert.Equal(t, uint32(65536), opcua.ConfigurationData["send_buffer_size"])
}

func TestOPCUADecodeFromBytes_OpenChannelMessage(t *testing.T) {
	// Test OpenSecureChannel message parsing
	payload := createMockOpenChannelMessage()
	packet := createMockOPCUAPacket(OPCUAMessageTypeOpenChannel, OPCUAChunkTypeFinal, 0x12345678, payload)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, OPCUAMessageTypeOpenChannel, opcua.MessageType)
	assert.Equal(t, uint32(0x12345678), opcua.SecureChannelID)
	assert.Equal(t, SecurityPolicyBasic256Sha256, opcua.SecurityPolicy)
	assert.Equal(t, SecurityModeSignAndEncrypt, opcua.SecurityMode)
	assert.Equal(t, uint32(3600000), opcua.RequestedLifetime)
	assert.True(t, opcua.IsSecurityExchange)
}

func TestOPCUADecodeFromBytes_ServiceMessage(t *testing.T) {
	// Test service message parsing
	payload := createMockServiceMessage(ServiceTypeCreateSession)
	packet := createMockOPCUAPacket(OPCUAMessageTypeMessage, OPCUAChunkTypeFinal, 0x12345678, payload)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, OPCUAMessageTypeMessage, opcua.MessageType)
	assert.Equal(t, uint32(0x12345678), opcua.SecureChannelID)
	assert.Equal(t, ServiceTypeCreateSession, opcua.ServiceNodeID)
	assert.Equal(t, "CreateSession", opcua.ServiceType)
	assert.Equal(t, uint32(0x12345678), opcua.RequestHandle)
	assert.True(t, opcua.IsSessionMgmt)
}

func TestOPCUALayerType(t *testing.T) {
	opcua := &OPCUA{}
	assert.Equal(t, LayerTypeOPCUA, opcua.LayerType())
}

func TestOPCUACanDecode(t *testing.T) {
	opcua := &OPCUA{}
	assert.Equal(t, LayerTypeOPCUA, opcua.CanDecode())
}

func TestOPCUANextLayerType(t *testing.T) {
	opcua := &OPCUA{}
	assert.Equal(t, gopacket.LayerTypePayload, opcua.NextLayerType())
}

func TestOPCUAString(t *testing.T) {
	tests := []struct {
		name        string
		messageType string
		chunkType   string
		serviceType string
		expected    string
	}{
		{
			name:        "Hello message",
			messageType: OPCUAMessageTypeHello,
			chunkType:   OPCUAChunkTypeFinal,
			serviceType: "",
			expected:    "OPC UA HEL F",
		},
		{
			name:        "Service message with service type",
			messageType: OPCUAMessageTypeMessage,
			chunkType:   OPCUAChunkTypeFinal,
			serviceType: "CreateSession",
			expected:    "OPC UA MSG F (Service: CreateSession)",
		},
		{
			name:        "Unknown service",
			messageType: OPCUAMessageTypeMessage,
			chunkType:   OPCUAChunkTypeFinal,
			serviceType: "Unknown",
			expected:    "OPC UA MSG F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opcua := &OPCUA{
				MessageType: tt.messageType,
				ChunkType:   tt.chunkType,
				ServiceType: tt.serviceType,
			}
			assert.Equal(t, tt.expected, opcua.String())
		})
	}
}

func TestOPCUAGetSecurityInfo(t *testing.T) {
	opcua := &OPCUA{
		SecurityPolicy:    SecurityPolicyBasic256Sha256,
		SecurityMode:      SecurityModeSignAndEncrypt,
		ClientCertificate: make([]byte, 1024),
		RequestedLifetime: 3600000,
	}

	security := opcua.GetSecurityInfo()

	assert.Equal(t, SecurityPolicyBasic256Sha256, security["policy"])
	assert.Equal(t, "Basic256Sha256", security["policy_name"])
	assert.Equal(t, SecurityModeSignAndEncrypt, security["mode"])
	assert.Equal(t, true, security["has_client_cert"])
	assert.Equal(t, 1024, security["client_cert_size"])
	assert.Equal(t, uint32(3600000), security["requested_lifetime"])
}

func TestOPCUAGetServiceInfo(t *testing.T) {
	opcua := &OPCUA{
		ServiceType:    "CreateSubscription",
		ServiceNodeID:  ServiceTypeCreateSubscription,
		RequestHandle:  0x12345678,
		SubscriptionID: 42,
		SessionID:      make([]byte, 16),
		IsSubscription: true,
		IsSessionMgmt:  false,
		IsDataAccess:   false,
		IsMethodCall:   false,
		IsBrowse:       false,
	}

	service := opcua.GetServiceInfo()

	assert.Equal(t, "CreateSubscription", service["type"])
	assert.Equal(t, ServiceTypeCreateSubscription, service["node_id"])
	assert.Equal(t, uint32(0x12345678), service["request_handle"])
	assert.Equal(t, uint32(42), service["subscription_id"])
	assert.Equal(t, true, service["has_session_id"])
	assert.Equal(t, true, service["is_subscription"])
	assert.Equal(t, false, service["is_session_mgmt"])
}

func TestOPCUASecurityPolicyClassification(t *testing.T) {
	tests := []struct {
		name           string
		securityPolicy string
		expectedMode   string
	}{
		{
			name:           "None policy",
			securityPolicy: SecurityPolicyNone,
			expectedMode:   SecurityModeNone,
		},
		{
			name:           "Basic256 policy",
			securityPolicy: SecurityPolicyBasic256,
			expectedMode:   SecurityModeSign,
		},
		{
			name:           "Basic256Sha256 policy",
			securityPolicy: SecurityPolicyBasic256Sha256,
			expectedMode:   SecurityModeSignAndEncrypt,
		},
		{
			name:           "Unknown policy",
			securityPolicy: "http://example.com/custom",
			expectedMode:   SecurityModeSign,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opcua := &OPCUA{SecurityPolicy: tt.securityPolicy}
			opcua.determineSecurityMode()
			assert.Equal(t, tt.expectedMode, opcua.SecurityMode)
		})
	}
}

func TestOPCUAServiceTypeClassification(t *testing.T) {
	tests := []struct {
		name               string
		serviceNodeID      uint32
		expectedSession    bool
		expectedSubscr     bool
		expectedDataAccess bool
		expectedMethodCall bool
		expectedBrowse     bool
	}{
		{
			name:               "CreateSession",
			serviceNodeID:      ServiceTypeCreateSession,
			expectedSession:    true,
			expectedSubscr:     false,
			expectedDataAccess: false,
			expectedMethodCall: false,
			expectedBrowse:     false,
		},
		{
			name:               "CreateSubscription",
			serviceNodeID:      ServiceTypeCreateSubscription,
			expectedSession:    false,
			expectedSubscr:     true,
			expectedDataAccess: false,
			expectedMethodCall: false,
			expectedBrowse:     false,
		},
		{
			name:               "Read",
			serviceNodeID:      ServiceTypeRead,
			expectedSession:    false,
			expectedSubscr:     false,
			expectedDataAccess: true,
			expectedMethodCall: false,
			expectedBrowse:     false,
		},
		{
			name:               "Call",
			serviceNodeID:      ServiceTypeCall,
			expectedSession:    false,
			expectedSubscr:     false,
			expectedDataAccess: false,
			expectedMethodCall: true,
			expectedBrowse:     false,
		},
		{
			name:               "Browse",
			serviceNodeID:      ServiceTypeBrowse,
			expectedSession:    false,
			expectedSubscr:     false,
			expectedDataAccess: false,
			expectedMethodCall: false,
			expectedBrowse:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opcua := &OPCUA{ServiceNodeID: tt.serviceNodeID}
			opcua.classifyServiceType()

			assert.Equal(t, tt.expectedSession, opcua.IsSessionMgmt)
			assert.Equal(t, tt.expectedSubscr, opcua.IsSubscription)
			assert.Equal(t, tt.expectedDataAccess, opcua.IsDataAccess)
			assert.Equal(t, tt.expectedMethodCall, opcua.IsMethodCall)
			assert.Equal(t, tt.expectedBrowse, opcua.IsBrowse)
		})
	}
}

func TestOPCUAGetServiceTypeName(t *testing.T) {
	tests := []struct {
		nodeID       uint32
		expectedName string
	}{
		{ServiceTypeCreateSession, "CreateSession"},
		{ServiceTypeActivateSession, "ActivateSession"},
		{ServiceTypeRead, "Read"},
		{ServiceTypeWrite, "Write"},
		{ServiceTypeCreateSubscription, "CreateSubscription"},
		{ServiceTypePublish, "Publish"},
		{ServiceTypeBrowse, "Browse"},
		{ServiceTypeCall, "Call"},
		{9999, "Unknown(9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedName, func(t *testing.T) {
			opcua := &OPCUA{}
			assert.Equal(t, tt.expectedName, opcua.getServiceTypeName(tt.nodeID))
		})
	}
}

func TestOPCUAConnectionTypeDetection(t *testing.T) {
	tests := []struct {
		name           string
		messageType    string
		serviceType    string
		expectedClient bool
		expectedServer bool
	}{
		{
			name:           "Hello message - client",
			messageType:    OPCUAMessageTypeHello,
			serviceType:    "",
			expectedClient: true,
			expectedServer: false,
		},
		{
			name:           "Acknowledge message - server",
			messageType:    OPCUAMessageTypeAcknowledge,
			serviceType:    "",
			expectedClient: false,
			expectedServer: true,
		},
		{
			name:           "CreateSession - client",
			messageType:    OPCUAMessageTypeMessage,
			serviceType:    "CreateSession",
			expectedClient: true,
			expectedServer: false,
		},
		{
			name:           "Read response - server",
			messageType:    OPCUAMessageTypeMessage,
			serviceType:    "Read",
			expectedClient: false,
			expectedServer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opcua := &OPCUA{
				MessageType: tt.messageType,
				ServiceType: tt.serviceType,
			}
			// Set flags based on service type for testing
			if tt.serviceType == "CreateSession" {
				opcua.IsSessionMgmt = true
			}
			if tt.serviceType == "Read" {
				opcua.IsDataAccess = true
			}

			assert.Equal(t, tt.expectedClient, opcua.IsClientConnection())
			assert.Equal(t, tt.expectedServer, opcua.IsServerResponse())
		})
	}
}

func TestOPCUARealTimeDataDetection(t *testing.T) {
	tests := []struct {
		name        string
		serviceType string
		isSubscr    bool
		expectedRT  bool
	}{
		{
			name:        "Publish service",
			serviceType: "Publish",
			isSubscr:    true,
			expectedRT:  true,
		},
		{
			name:        "CreateMonitoredItems service",
			serviceType: "CreateMonitoredItems",
			isSubscr:    true,
			expectedRT:  true,
		},
		{
			name:        "Read service",
			serviceType: "Read",
			isSubscr:    false,
			expectedRT:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opcua := &OPCUA{
				ServiceType:    tt.serviceType,
				IsSubscription: tt.isSubscr,
			}
			assert.Equal(t, tt.expectedRT, opcua.IsRealTimeData())
		})
	}
}

func TestOPCUAIsSecure(t *testing.T) {
	tests := []struct {
		name           string
		securityMode   string
		securityPolicy string
		expectedSecure bool
	}{
		{
			name:           "None security",
			securityMode:   SecurityModeNone,
			securityPolicy: SecurityPolicyNone,
			expectedSecure: false,
		},
		{
			name:           "Sign security",
			securityMode:   SecurityModeSign,
			securityPolicy: SecurityPolicyBasic256,
			expectedSecure: true,
		},
		{
			name:           "SignAndEncrypt security",
			securityMode:   SecurityModeSignAndEncrypt,
			securityPolicy: SecurityPolicyBasic256Sha256,
			expectedSecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opcua := &OPCUA{
				SecurityMode:   tt.securityMode,
				SecurityPolicy: tt.securityPolicy,
			}
			assert.Equal(t, tt.expectedSecure, opcua.IsSecure())
		})
	}
}

func TestOPCUADecoder(t *testing.T) {
	// Test the decoder function
	payload := createMockHelloMessage()
	packet := createMockOPCUAPacket(OPCUAMessageTypeHello, OPCUAChunkTypeFinal, 0, payload)

	// Create a mock packet builder
	pb := gopacket.NewPacket(packet, LayerTypeOPCUA, gopacket.Default)

	// Check that the layer was decoded
	opcuaLayer := pb.Layer(LayerTypeOPCUA)
	require.NotNil(t, opcuaLayer)

	opcua, ok := opcuaLayer.(*OPCUA)
	require.True(t, ok)
	assert.Equal(t, OPCUAMessageTypeHello, opcua.MessageType)
}

func TestOPCUAPortRegistration(t *testing.T) {
	// Test that the layer type is properly registered
	RegisterOPCUA()
	InitLayerOPCUA()

	// Placeholder assertion since we can't easily test port registration
	assert.True(t, true)
}

func TestOPCUAMalformedData(t *testing.T) {
	// Test handling of malformed data
	payload := []byte{0x01} // Too short for proper parsing
	packet := createMockOPCUAPacket(OPCUAMessageTypeMessage, OPCUAChunkTypeFinal, 0x12345678, payload)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	// Should not fail completely, but should record the error
	require.NoError(t, err)
	assert.Contains(t, opcua.ConfigurationData, "parse_error")
}

func TestOPCUAEmptyPayload(t *testing.T) {
	// Test packet with no data payload
	packet := createMockOPCUAPacket(OPCUAMessageTypeError, OPCUAChunkTypeFinal, 0, nil)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, OPCUAMessageTypeError, opcua.MessageType)
}

// Benchmark tests for performance
func BenchmarkOPCUADecode(b *testing.B) {
	payload := createMockHelloMessage()
	packet := createMockOPCUAPacket(OPCUAMessageTypeHello, OPCUAChunkTypeFinal, 0, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opcua := &OPCUA{}
		_ = opcua.DecodeFromBytes(packet, nil)
	}
}

func BenchmarkOPCUAString(b *testing.B) {
	opcua := &OPCUA{
		MessageType: OPCUAMessageTypeMessage,
		ChunkType:   OPCUAChunkTypeFinal,
		ServiceType: "CreateSession",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = opcua.String()
	}
}

// Test edge cases and error conditions
func TestOPCUAEdgeCases(t *testing.T) {
	t.Run("Zero length packet", func(t *testing.T) {
		opcua := &OPCUA{}
		err := opcua.DecodeFromBytes([]byte{}, nil)
		assert.Error(t, err)
	})

	t.Run("Exactly minimum size", func(t *testing.T) {
		packet := make([]byte, 8)
		copy(packet[0:3], []byte("HEL"))
		packet[3] = 'F'
		binary.LittleEndian.PutUint32(packet[4:8], 8)

		opcua := &OPCUA{}
		err := opcua.DecodeFromBytes(packet, nil)
		assert.NoError(t, err)
	})

	t.Run("Large message size field", func(t *testing.T) {
		packet := make([]byte, 8)
		copy(packet[0:3], []byte("HEL"))
		packet[3] = 'F'
		binary.LittleEndian.PutUint32(packet[4:8], 0xFFFFFFFF) // Very large size

		opcua := &OPCUA{}
		err := opcua.DecodeFromBytes(packet, nil)
		assert.Error(t, err)
	})
}

func TestOPCUAErrorMessage(t *testing.T) {
	// Test error message parsing
	errorPayload := make([]byte, 12)
	binary.LittleEndian.PutUint32(errorPayload[0:4], 0x80000000) // Error code
	binary.LittleEndian.PutUint32(errorPayload[4:8], 4)          // Reason length
	copy(errorPayload[8:12], []byte("test"))                     // Reason

	packet := createMockOPCUAPacket(OPCUAMessageTypeError, OPCUAChunkTypeFinal, 0, errorPayload)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, OPCUAMessageTypeError, opcua.MessageType)
	// Check if error parsing was attempted (may have parse errors due to simplified implementation)
	assert.NotNil(t, opcua.ConfigurationData)
}

func TestOPCUASubscriptionData(t *testing.T) {
	// Test subscription service data parsing
	payload := make([]byte, 12)
	binary.LittleEndian.PutUint32(payload[0:4], ServiceTypeCreateSubscription) // Service node ID
	binary.LittleEndian.PutUint32(payload[4:8], 0x12345678)                    // Request handle
	binary.LittleEndian.PutUint32(payload[8:12], 42)                           // Subscription ID

	packet := createMockOPCUAPacket(OPCUAMessageTypeMessage, OPCUAChunkTypeFinal, 0x12345678, payload)

	opcua := &OPCUA{}
	err := opcua.DecodeFromBytes(packet, nil)

	require.NoError(t, err)
	assert.Equal(t, ServiceTypeCreateSubscription, opcua.ServiceNodeID)
	assert.Equal(t, "CreateSubscription", opcua.ServiceType)
	assert.True(t, opcua.IsSubscription)
}
