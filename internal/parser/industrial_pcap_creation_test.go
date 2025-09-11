package parser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIndustrialPCAPCreation tests that industrial PCAP files are created correctly
func TestIndustrialPCAPCreation(t *testing.T) {
	tests := []struct {
		name       string
		createFunc func(*testing.T) string
		minSize    int64
	}{
		{
			name:       "EtherNet/IP PCAP",
			createFunc: createTestEtherNetIPPCAP,
			minSize:    400, // Minimum expected file size
		},
		{
			name:       "OPC UA PCAP",
			createFunc: createTestOPCUAPCAP,
			minSize:    600,
		},
		{
			name:       "Mixed Protocols PCAP",
			createFunc: createTestMixedProtocolsPCAP,
			minSize:    500,
		},
		{
			name:       "Malformed Industrial PCAP",
			createFunc: createTestMalformedIndustrialPCAP,
			minSize:    300,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create the PCAP file
			filename := tt.createFunc(t)
			defer os.Remove(filename)

			// Verify file exists and has reasonable size
			fileInfo, err := os.Stat(filename)
			require.NoError(t, err, "PCAP file should exist")
			assert.Greater(t, fileInfo.Size(), tt.minSize, "PCAP file should have reasonable size")

			// Verify file is readable
			file, err := os.Open(filename)
			require.NoError(t, err, "PCAP file should be readable")
			defer file.Close()

			// Read first few bytes to verify it's a valid PCAP file
			header := make([]byte, 4)
			n, err := file.Read(header)
			require.NoError(t, err, "Should be able to read PCAP header")
			require.Equal(t, 4, n, "Should read 4 bytes of header")

			// Check for PCAP magic number (little-endian or big-endian)
			magicLE := []byte{0xD4, 0xC3, 0xB2, 0xA1} // Little-endian
			magicBE := []byte{0xA1, 0xB2, 0xC3, 0xD4} // Big-endian

			validMagic := assert.Equal(t, magicLE, header, "Should have little-endian PCAP magic") ||
				assert.Equal(t, magicBE, header, "Should have big-endian PCAP magic")

			assert.True(t, validMagic, "PCAP file should have valid magic number")

			t.Logf("Successfully created %s with size %d bytes", tt.name, fileInfo.Size())
		})
	}
}

// TestIndustrialProtocolDataCreation tests the protocol data creation functions
func TestIndustrialProtocolDataCreation(t *testing.T) {
	tests := []struct {
		name       string
		createFunc func() []byte
		minSize    int
		maxSize    int
	}{
		{
			name:       "EtherNet/IP List Identity Command",
			createFunc: createEtherNetIPListIdentityCommand,
			minSize:    24,
			maxSize:    24,
		},
		{
			name:       "EtherNet/IP List Identity Response",
			createFunc: createEtherNetIPListIdentityResponse,
			minSize:    40,
			maxSize:    100,
		},
		{
			name:       "EtherNet/IP Explicit Data",
			createFunc: createEtherNetIPExplicitData,
			minSize:    30,
			maxSize:    50,
		},
		{
			name:       "EtherNet/IP Implicit Data",
			createFunc: createEtherNetIPImplicitData,
			minSize:    30,
			maxSize:    40,
		},
		{
			name:       "OPC UA Hello Message",
			createFunc: createOPCUAHelloMessage,
			minSize:    32,
			maxSize:    32,
		},
		{
			name:       "OPC UA Acknowledge Message",
			createFunc: createOPCUAAcknowledgeMessage,
			minSize:    28,
			maxSize:    28,
		},
		{
			name:       "OPC UA Open Channel Message",
			createFunc: createOPCUAOpenChannelMessage,
			minSize:    80,
			maxSize:    200,
		},
		{
			name:       "OPC UA Create Session Message",
			createFunc: createOPCUACreateSessionMessage,
			minSize:    20,
			maxSize:    20,
		},
		{
			name:       "OPC UA Read Message",
			createFunc: createOPCUAReadMessage,
			minSize:    24,
			maxSize:    24,
		},
		{
			name:       "OPC UA Subscription Message",
			createFunc: createOPCUASubscriptionMessage,
			minSize:    32,
			maxSize:    32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.createFunc()

			assert.NotNil(t, data, "Protocol data should not be nil")
			assert.GreaterOrEqual(t, len(data), tt.minSize, "Protocol data should meet minimum size")
			assert.LessOrEqual(t, len(data), tt.maxSize, "Protocol data should not exceed maximum size")

			// Verify data is not all zeros (should have some content)
			hasNonZero := false
			for _, b := range data {
				if b != 0 {
					hasNonZero = true
					break
				}
			}
			assert.True(t, hasNonZero, "Protocol data should contain non-zero bytes")

			t.Logf("Successfully created %s with %d bytes", tt.name, len(data))
		})
	}
}
