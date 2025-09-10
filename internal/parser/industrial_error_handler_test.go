package parser

import (
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndustrialProtocolError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *IndustrialProtocolError
		expected string
	}{
		{
			name: "error with packet",
			err: &IndustrialProtocolError{
				Protocol:  "ethernetip",
				Packet:    createMockPacket(t, 100),
				Err:       errors.New("test error"),
				Context:   "test context",
				Timestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			expected: "industrial protocol error [ethernetip] at 2023-01-01T12:00:00Z: test context - test error (packet length: 100)",
		},
		{
			name: "error without packet",
			err: &IndustrialProtocolError{
				Protocol:  "opcua",
				Packet:    nil,
				Err:       errors.New("test error"),
				Context:   "test context",
				Timestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			expected: "industrial protocol error [opcua] at 2023-01-01T12:00:00Z: test context - test error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestIndustrialProtocolError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	protocolErr := &IndustrialProtocolError{
		Err: originalErr,
	}

	assert.Equal(t, originalErr, protocolErr.Unwrap())
}

func TestIndustrialProtocolError_IsRecoverable(t *testing.T) {
	tests := []struct {
		name        string
		recoverable bool
	}{
		{"recoverable error", true},
		{"non-recoverable error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &IndustrialProtocolError{
				Recoverable: tt.recoverable,
			}
			assert.Equal(t, tt.recoverable, err.IsRecoverable())
		})
	}
}

func TestIndustrialProtocolError_GetPacketInfo(t *testing.T) {
	tests := []struct {
		name     string
		err      *IndustrialProtocolError
		expected map[string]interface{}
	}{
		{
			name: "with packet and raw data",
			err: &IndustrialProtocolError{
				Packet:     createMockPacket(t, 100),
				PacketData: []byte{0x01, 0x02, 0x03, 0x04},
			},
			expected: map[string]interface{}{
				"timestamp":        time.Time{},
				"length":           100,
				"truncated":        false,
				"interface_index":  0,
				"raw_data_length":  4,
				"raw_data_preview": "01020304",
			},
		},
		{
			name: "with large raw data",
			err: &IndustrialProtocolError{
				Packet:     createMockPacket(t, 100),
				PacketData: make([]byte, 100), // Large data
			},
			expected: map[string]interface{}{
				"timestamp":        time.Time{},
				"length":           100,
				"truncated":        false,
				"interface_index":  0,
				"raw_data_length":  100,
				"raw_data_preview": strings.Repeat("00", 64) + "...",
			},
		},
		{
			name: "without packet",
			err: &IndustrialProtocolError{
				Packet: nil,
			},
			expected: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.err.GetPacketInfo()

			// Check all expected keys exist
			for key, expectedValue := range tt.expected {
				actualValue, exists := info[key]
				assert.True(t, exists, "Expected key %s to exist", key)
				assert.Equal(t, expectedValue, actualValue, "Value mismatch for key %s", key)
			}
		})
	}
}

func TestDefaultErrorHandler_HandleProtocolError(t *testing.T) {
	var logOutput strings.Builder
	logger := log.New(&logOutput, "", 0)
	handler := NewDefaultErrorHandler(logger)

	tests := []struct {
		name        string
		err         *IndustrialProtocolError
		expectError bool
		logContains string
	}{
		{
			name: "recoverable error",
			err: &IndustrialProtocolError{
				Protocol:    "ethernetip",
				Err:         errors.New("test error"),
				Context:     "test context",
				Recoverable: true,
			},
			expectError: false,
			logContains: "WARN: Recoverable protocol error",
		},
		{
			name: "non-recoverable error",
			err: &IndustrialProtocolError{
				Protocol:    "opcua",
				Err:         errors.New("test error"),
				Context:     "test context",
				Recoverable: false,
			},
			expectError: false,
			logContains: "ERROR: Non-recoverable protocol error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput.Reset()
			handler.ResetErrorCount()

			err := handler.HandleProtocolError(tt.err)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Contains(t, logOutput.String(), tt.logContains)
			assert.Equal(t, 1, handler.GetErrorCount())
		})
	}
}

func TestDefaultErrorHandler_ErrorThreshold(t *testing.T) {
	handler := NewDefaultErrorHandler(nil)
	handler.SetErrorThreshold(3)

	// Add errors up to threshold - 1
	for i := 0; i < 2; i++ {
		err := &IndustrialProtocolError{
			Protocol:    "test",
			Err:         errors.New("test error"),
			Recoverable: false,
		}
		assert.NoError(t, handler.HandleProtocolError(err))
		assert.False(t, handler.IsErrorThresholdExceeded())
	}

	// Add one more error to reach threshold - this should return error because threshold is reached
	err := &IndustrialProtocolError{
		Protocol:    "test",
		Err:         errors.New("test error"),
		Recoverable: false,
	}
	result := handler.HandleProtocolError(err)
	assert.Error(t, result)
	assert.True(t, handler.IsErrorThresholdExceeded())
	assert.Contains(t, result.Error(), "error threshold exceeded")

	// Test that recoverable errors don't cause the handler to return errors even after threshold
	handler.ResetErrorCount()
	handler.SetErrorThreshold(1)

	recoverableErr := &IndustrialProtocolError{
		Protocol:    "test",
		Err:         errors.New("recoverable error"),
		Recoverable: true,
	}
	assert.NoError(t, handler.HandleProtocolError(recoverableErr))
	assert.True(t, handler.IsErrorThresholdExceeded())

	// Even after threshold exceeded, recoverable errors should not return error
	assert.NoError(t, handler.HandleProtocolError(recoverableErr))
}

func TestDefaultErrorHandler_HandleClassificationError(t *testing.T) {
	var logOutput strings.Builder
	logger := log.New(&logOutput, "", 0)
	handler := NewDefaultErrorHandler(logger)

	err := handler.HandleClassificationError("device123", errors.New("classification failed"))

	assert.NoError(t, err)
	assert.Equal(t, 1, handler.GetErrorCount())
	assert.Contains(t, logOutput.String(), "WARN: Device classification error for device device123")
}

func TestDefaultErrorHandler_HandleValidationError(t *testing.T) {
	var logOutput strings.Builder
	logger := log.New(&logOutput, "", 0)
	handler := NewDefaultErrorHandler(logger)

	testData := map[string]interface{}{"test": "data"}
	err := handler.HandleValidationError(testData, errors.New("validation failed"))

	assert.NoError(t, err)
	assert.Equal(t, 1, handler.GetErrorCount())
	assert.Contains(t, logOutput.String(), "WARN: Data validation error")
}

func TestNoOpErrorHandler(t *testing.T) {
	handler := NewNoOpErrorHandler()

	// Test all methods return expected no-op values
	protocolErr := &IndustrialProtocolError{
		Protocol: "test",
		Err:      errors.New("test error"),
	}

	assert.NoError(t, handler.HandleProtocolError(protocolErr))
	assert.NoError(t, handler.HandleClassificationError("device", errors.New("error")))
	assert.NoError(t, handler.HandleValidationError("data", errors.New("error")))
	assert.Equal(t, 0, handler.GetErrorCount())
	assert.False(t, handler.IsErrorThresholdExceeded())

	handler.SetErrorThreshold(100)
	handler.ResetErrorCount()

	// Should still return no-op values
	assert.Equal(t, 0, handler.GetErrorCount())
	assert.False(t, handler.IsErrorThresholdExceeded())
}

func TestNewMalformedPacketError(t *testing.T) {
	packet := createMockPacket(t, 64)
	originalErr := errors.New("malformed data")

	err := NewMalformedPacketError("ethernetip", packet, originalErr, "test context")

	assert.Equal(t, "ethernetip", err.Protocol)
	assert.Equal(t, packet, err.Packet)
	assert.Equal(t, originalErr, err.Err)
	assert.Equal(t, "test context", err.Context)
	assert.True(t, err.Recoverable)
	assert.NotEmpty(t, err.PacketData)
}

func TestNewIncompleteDataError(t *testing.T) {
	packet := createMockPacket(t, 32)

	err := NewIncompleteDataError("opcua", packet, 64, 32, "test context")

	assert.Equal(t, "opcua", err.Protocol)
	assert.Equal(t, packet, err.Packet)
	assert.Equal(t, "test context", err.Context)
	assert.True(t, err.Recoverable)
	assert.Contains(t, err.Error(), "expected 64 bytes, got 32 bytes")
}

func TestNewProtocolDetectionError(t *testing.T) {
	packet := createMockPacket(t, 64)
	originalErr := errors.New("detection failed")

	err := NewProtocolDetectionError("modbus", packet, originalErr, "test context")

	assert.Equal(t, "modbus", err.Protocol)
	assert.Equal(t, packet, err.Packet)
	assert.Equal(t, originalErr, err.Err)
	assert.Equal(t, "test context", err.Context)
	assert.True(t, err.Recoverable)
}

func TestNewParsingError(t *testing.T) {
	packet := createMockPacket(t, 64)
	originalErr := errors.New("parsing failed")

	tests := []struct {
		name        string
		recoverable bool
	}{
		{"recoverable parsing error", true},
		{"non-recoverable parsing error", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewParsingError("profinet", packet, originalErr, "test context", tt.recoverable)

			assert.Equal(t, "profinet", err.Protocol)
			assert.Equal(t, packet, err.Packet)
			assert.Equal(t, originalErr, err.Err)
			assert.Equal(t, "test context", err.Context)
			assert.Equal(t, tt.recoverable, err.Recoverable)
		})
	}
}

// Helper function to create a mock packet for testing
func createMockPacket(t *testing.T, length int) gopacket.Packet {
	// Create a simple Ethernet frame
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
		SrcPort: 12345,
		DstPort: 44818, // EtherNet/IP port
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
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Set metadata to match expected length
	packet.Metadata().Length = length

	return packet
}

// Benchmark tests for error handling performance
func BenchmarkDefaultErrorHandler_HandleProtocolError(b *testing.B) {
	handler := NewDefaultErrorHandler(log.New(io.Discard, "", 0))
	err := &IndustrialProtocolError{
		Protocol:    "ethernetip",
		Err:         errors.New("test error"),
		Context:     "benchmark test",
		Recoverable: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.HandleProtocolError(err)
	}
}

func BenchmarkNoOpErrorHandler_HandleProtocolError(b *testing.B) {
	handler := NewNoOpErrorHandler()
	err := &IndustrialProtocolError{
		Protocol:    "ethernetip",
		Err:         errors.New("test error"),
		Context:     "benchmark test",
		Recoverable: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.HandleProtocolError(err)
	}
}

func BenchmarkIndustrialProtocolError_Error(b *testing.B) {
	packet := createMockPacket(&testing.T{}, 100)
	err := &IndustrialProtocolError{
		Protocol:  "ethernetip",
		Packet:    packet,
		Err:       errors.New("test error"),
		Context:   "benchmark test",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err.Error()
	}
}
