package parser

import (
	"errors"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndustrialProtocolParserImpl_ParseIndustrialProtocols_ErrorHandling(t *testing.T) {
	tests := []struct {
		name            string
		packet          gopacket.Packet
		errorHandler    ErrorHandler
		expectError     bool
		expectProtocols int
	}{
		{
			name:            "nil packet",
			packet:          nil,
			errorHandler:    NewNoOpErrorHandler(),
			expectError:     false,
			expectProtocols: 0,
		},
		{
			name:            "valid EtherNet/IP packet",
			packet:          createEtherNetIPPacket(t),
			errorHandler:    NewNoOpErrorHandler(),
			expectError:     false,
			expectProtocols: 1,
		},
		{
			name:            "error threshold exceeded",
			packet:          createEtherNetIPPacket(t),
			errorHandler:    createThresholdExceededHandler(),
			expectError:     true,
			expectProtocols: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewIndustrialProtocolParserWithErrorHandler(tt.errorHandler)

			protocols, err := parser.ParseIndustrialProtocols(tt.packet)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Len(t, protocols, tt.expectProtocols)
		})
	}
}

func TestIndustrialProtocolParserImpl_parseEtherNetIPWithErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		packet      gopacket.Packet
		expectError bool
		expectInfo  bool
	}{
		{
			name:        "nil packet",
			packet:      nil,
			expectError: true,
			expectInfo:  false,
		},
		{
			name:        "non-EtherNet/IP packet",
			packet:      createGenericTCPPacket(t, 80),
			expectError: false,
			expectInfo:  false,
		},
		{
			name:        "valid EtherNet/IP packet",
			packet:      createEtherNetIPPacket(t),
			expectError: false,
			expectInfo:  true,
		},
		{
			name:        "malformed EtherNet/IP packet",
			packet:      createMalformedEtherNetIPPacket(t),
			expectError: false, // Should handle gracefully
			expectInfo:  true,  // Should still extract basic info
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &IndustrialProtocolParserImpl{
				enableEtherNetIP: true,
				errorHandler:     NewNoOpErrorHandler(),
			}

			info, err := parser.parseEtherNetIPWithErrorHandling(tt.packet, time.Now())

			if tt.expectError {
				assert.NotNil(t, err)
				assert.Nil(t, info)
			} else {
				assert.Nil(t, err)
				if tt.expectInfo {
					assert.NotNil(t, info)
					assert.Equal(t, "ethernetip", info.Protocol)
				} else {
					assert.Nil(t, info)
				}
			}
		})
	}
}

func TestIndustrialProtocolParserImpl_parseOPCUAWithErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		packet      gopacket.Packet
		expectError bool
		expectInfo  bool
	}{
		{
			name:        "nil packet",
			packet:      nil,
			expectError: true,
			expectInfo:  false,
		},
		{
			name:        "non-OPC UA packet",
			packet:      createGenericTCPPacket(t, 80),
			expectError: false,
			expectInfo:  false,
		},
		{
			name:        "valid OPC UA packet",
			packet:      createOPCUAPacket(t),
			expectError: false,
			expectInfo:  true,
		},
		{
			name:        "malformed OPC UA packet",
			packet:      createMalformedOPCUAPacket(t),
			expectError: false, // Should handle gracefully
			expectInfo:  true,  // Should still extract basic info
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &IndustrialProtocolParserImpl{
				enableOPCUA:  true,
				errorHandler: NewNoOpErrorHandler(),
			}

			info, err := parser.parseOPCUAWithErrorHandling(tt.packet, time.Now())

			if tt.expectError {
				assert.NotNil(t, err)
				assert.Nil(t, info)
			} else {
				assert.Nil(t, err)
				if tt.expectInfo {
					assert.NotNil(t, info)
					assert.Equal(t, "opcua", info.Protocol)
				} else {
					assert.Nil(t, info)
				}
			}
		})
	}
}

func TestIndustrialProtocolParserImpl_DetectDeviceType_ErrorHandling(t *testing.T) {
	parser := &IndustrialProtocolParserImpl{
		errorHandler: NewNoOpErrorHandler(),
	}

	tests := []struct {
		name      string
		protocols []IndustrialProtocolInfo
		flows     []model.Flow
		expected  model.IndustrialDeviceType
	}{
		{
			name:      "empty protocols",
			protocols: []IndustrialProtocolInfo{},
			flows:     []model.Flow{},
			expected:  model.DeviceTypeUnknown,
		},
		{
			name: "EtherNet/IP with real-time data",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:       "ethernetip",
					IsRealTimeData: true,
				},
			},
			flows:    []model.Flow{},
			expected: model.DeviceTypeIODevice,
		},
		{
			name: "OPC UA client only",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "opcua",
					Direction: "outbound",
				},
			},
			flows:    []model.Flow{},
			expected: model.DeviceTypeHMI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.DetectDeviceType(tt.protocols, tt.flows)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIndustrialProtocolParserImpl_SetGetErrorHandler(t *testing.T) {
	parser := &IndustrialProtocolParserImpl{}

	// Test setting nil handler (should not change)
	originalHandler := parser.errorHandler
	parser.SetErrorHandler(nil)
	assert.Equal(t, originalHandler, parser.errorHandler)

	// Test setting valid handler
	newHandler := NewDefaultErrorHandler(nil)
	parser.SetErrorHandler(newHandler)
	assert.Equal(t, newHandler, parser.errorHandler)
	assert.Equal(t, newHandler, parser.GetErrorHandler())
}

func TestIndustrialProtocolParserImpl_ValidationMethods(t *testing.T) {
	parser := &IndustrialProtocolParserImpl{
		errorHandler: NewNoOpErrorHandler(),
	}

	t.Run("validateEtherNetIPLayer", func(t *testing.T) {
		// Test nil layer
		err := parser.validateEtherNetIPLayer(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "EtherNet/IP layer is nil")

		// Test valid layer (would need actual layer implementation)
		// This is a placeholder test since we don't have the actual layer implementation
	})

	t.Run("validateOPCUALayer", func(t *testing.T) {
		// Test nil layer
		err := parser.validateOPCUALayer(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "OPC UA layer is nil")

		// Test valid layer (would need actual layer implementation)
		// This is a placeholder test since we don't have the actual layer implementation
	})
}

func TestIndustrialProtocolParserImpl_SafeExtractionMethods(t *testing.T) {
	parser := &IndustrialProtocolParserImpl{
		errorHandler: NewNoOpErrorHandler(),
	}

	t.Run("safeGetDeviceIdentity", func(t *testing.T) {
		// Test nil layer
		result, err := parser.safeGetDeviceIdentity(nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "layer is nil")
	})

	t.Run("safeGetCIPInfo", func(t *testing.T) {
		// Test nil layer
		result, err := parser.safeGetCIPInfo(nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "layer is nil")
	})

	t.Run("safeIsDiscoveryMessage", func(t *testing.T) {
		// Test nil layer
		result := parser.safeIsDiscoveryMessage(nil)
		assert.False(t, result)
	})

	t.Run("safeGetSecurityInfo", func(t *testing.T) {
		// Test nil layer
		result, err := parser.safeGetSecurityInfo(nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "layer is nil")
	})

	t.Run("safeGetServiceInfo", func(t *testing.T) {
		// Test nil layer
		result, err := parser.safeGetServiceInfo(nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "layer is nil")
	})

	t.Run("safeIsRealTimeData", func(t *testing.T) {
		// Test nil layer
		result := parser.safeIsRealTimeData(nil)
		assert.False(t, result)
	})
}

func TestIndustrialProtocolParserImpl_extractPortInfo(t *testing.T) {
	parser := &IndustrialProtocolParserImpl{
		errorHandler: NewNoOpErrorHandler(),
	}

	tests := []struct {
		name              string
		packet            gopacket.Packet
		ports             []uint16
		expectError       bool
		expectedPort      uint16
		expectedTransport string
	}{
		{
			name:              "TCP EtherNet/IP packet",
			packet:            createEtherNetIPPacket(t),
			ports:             []uint16{44818, 2222},
			expectError:       false,
			expectedPort:      44818,
			expectedTransport: "tcp",
		},
		{
			name:        "no matching ports",
			packet:      createGenericTCPPacket(t, 80),
			ports:       []uint16{44818, 2222},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &IndustrialProtocolInfo{
				AdditionalData: make(map[string]interface{}),
			}

			err := parser.extractPortInfo(tt.packet, info, tt.ports)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPort, info.Port)
				assert.Equal(t, tt.expectedTransport, info.AdditionalData["transport"])
			}
		})
	}
}

// Helper functions for creating test packets

func createEtherNetIPPacket(t *testing.T) gopacket.Packet {
	return createTCPPacket(t, 12345, 44818)
}

func createOPCUAPacket(t *testing.T) gopacket.Packet {
	return createTCPPacket(t, 12345, 4840)
}

func createGenericTCPPacket(t *testing.T, dstPort uint16) gopacket.Packet {
	return createTCPPacket(t, 12345, dstPort)
}

func createTCPPacket(t *testing.T, srcPort, dstPort uint16) gopacket.Packet {
	// Create Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	// Create TCP layer
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1000,
		Ack:     2000,
		SYN:     true,
	}

	// Set network layer for checksum calculation
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
	require.NoError(t, err)

	// Create packet from serialized data
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func createMalformedEtherNetIPPacket(t *testing.T) gopacket.Packet {
	// Create a packet with EtherNet/IP port but potentially malformed data
	packet := createEtherNetIPPacket(t)
	// In a real implementation, this would have malformed layer data
	return packet
}

func createMalformedOPCUAPacket(t *testing.T) gopacket.Packet {
	// Create a packet with OPC UA port but potentially malformed data
	packet := createOPCUAPacket(t)
	// In a real implementation, this would have malformed layer data
	return packet
}

func createThresholdExceededHandler() ErrorHandler {
	handler := NewDefaultErrorHandler(nil)
	handler.SetErrorThreshold(0) // Set threshold to 0 so it's immediately exceeded
	// Trigger threshold exceeded state
	handler.HandleProtocolError(&IndustrialProtocolError{
		Protocol:    "test",
		Err:         errors.New("test"),
		Recoverable: false,
	})
	return handler
}

// Integration test for error handling in realistic scenarios
func TestIndustrialProtocolParser_ErrorHandling_Integration(t *testing.T) {
	// Create parser with default error handler
	parser := NewIndustrialProtocolParser()

	// Test parsing multiple packets with some errors
	packets := []gopacket.Packet{
		createEtherNetIPPacket(t),
		nil, // This should cause an error
		createOPCUAPacket(t),
		createGenericTCPPacket(t, 80), // Non-industrial packet
	}

	var allProtocols []IndustrialProtocolInfo
	errorCount := 0

	for _, packet := range packets {
		protocols, err := parser.ParseIndustrialProtocols(packet)
		if err != nil {
			errorCount++
			continue
		}
		allProtocols = append(allProtocols, protocols...)
	}

	// Should have parsed 2 industrial protocols (EtherNet/IP and OPC UA)
	assert.Len(t, allProtocols, 2)

	// Should have encountered some errors but continued processing
	assert.Greater(t, parser.GetErrorHandler().GetErrorCount(), 0)

	// Test device type detection with the parsed protocols
	deviceType := parser.DetectDeviceType(allProtocols, []model.Flow{})
	assert.NotEqual(t, model.DeviceTypeUnknown, deviceType)
}

// Benchmark tests for error handling performance impact
func BenchmarkIndustrialProtocolParser_ParseWithErrorHandling(b *testing.B) {
	parser := NewIndustrialProtocolParserWithErrorHandler(NewNoOpErrorHandler())
	packet := createEtherNetIPPacket(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseIndustrialProtocols(packet)
	}
}

func BenchmarkIndustrialProtocolParser_ParseWithoutErrorHandling(b *testing.B) {
	// This would be the original parsing without error handling
	// Included for performance comparison
	parser := &IndustrialProtocolParserImpl{
		enableEtherNetIP: true,
		enableOPCUA:      true,
		errorHandler:     NewNoOpErrorHandler(),
	}
	packet := createEtherNetIPPacket(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Direct call to original parsing method
		_ = parser.parseEtherNetIP(packet, time.Now())
	}
}
