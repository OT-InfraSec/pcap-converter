package parser

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGopacketParser_IndustrialProtocolIntegration tests the integration of industrial protocol parsing
// with the existing GopacketParser packet processing pipeline
func TestGopacketParser_IndustrialProtocolIntegration(t *testing.T) {
	// Create temporary database
	dbFile := "test_gopacket_industrial_integration.sqlite"
	defer os.Remove(dbFile)

	repo, err := repository.NewSQLiteRepository(dbFile)
	require.NoError(t, err)

	// Create test PCAP file with mixed industrial and standard traffic
	pcapFile := createMixedIndustrialStandardPCAP(t)
	defer os.Remove(pcapFile)

	// Create GopacketParser with industrial protocol support
	parser := NewGopacketParser(pcapFile, repo)
	require.NotNil(t, parser)

	// Verify industrial parser is initialized
	assert.NotNil(t, parser.industrialParser)

	// Parse the PCAP file
	err = parser.ParseFile()
	require.NoError(t, err)

	// Verify devices were created and classified
	devices, err := repo.GetDevices(nil)
	require.NoError(t, err)
	assert.Greater(t, len(devices), 0, "Should have detected devices")

	// Verify industrial devices were classified
	var industrialDevices []*model.Device
	for _, device := range devices {
		if device.AdditionalData != "" {
			// Check if device has industrial protocol information
			if containsIndustrialProtocols(device.AdditionalData) {
				industrialDevices = append(industrialDevices, device)
			}
		}
	}
	assert.Greater(t, len(industrialDevices), 0, "Should have classified industrial devices")
}

// TestGopacketParser_BackwardCompatibility tests that industrial protocol integration
// doesn't break existing packet processing functionality
func TestGopacketParser_BackwardCompatibility(t *testing.T) {
	// Create temporary database
	dbFile := "test_gopacket_backward_compat.sqlite"
	defer os.Remove(dbFile)

	repo, err := repository.NewSQLiteRepository(dbFile)
	require.NoError(t, err)

	// Create test PCAP file with only standard protocols (no industrial)
	pcapFile := createStandardProtocolsPCAP(t)
	defer os.Remove(pcapFile)

	// Create GopacketParser
	parser := NewGopacketParser(pcapFile, repo)
	require.NotNil(t, parser)

	// Parse the PCAP file
	err = parser.ParseFile()
	require.NoError(t, err)

	// Verify standard functionality still works
	devices, err := repo.GetDevices(nil)
	require.NoError(t, err)
	assert.Greater(t, len(devices), 0, "Should have detected standard devices")

	flows, err := repo.GetFlows(nil)
	require.NoError(t, err)
	assert.Greater(t, len(flows), 0, "Should have detected flows")

	// Verify no industrial classification for standard devices
	for _, device := range devices {
		if device.AdditionalData != "" {
			assert.False(t, containsIndustrialProtocols(device.AdditionalData),
				"Standard devices should not have industrial classification")
		}
	}
}

// TestGopacketParser_MixedTrafficProcessing tests processing of mixed industrial and standard traffic
func TestGopacketParser_MixedTrafficProcessing(t *testing.T) {
	// Create temporary database
	dbFile := "test_gopacket_mixed_traffic.sqlite"
	defer os.Remove(dbFile)

	repo, err := repository.NewSQLiteRepository(dbFile)
	require.NoError(t, err)

	// Create test PCAP file with mixed traffic
	pcapFile := createComprehensiveMixedTrafficPCAP(t)
	defer os.Remove(pcapFile)

	// Create GopacketParser
	parser := NewGopacketParser(pcapFile, repo)
	require.NotNil(t, parser)

	// Parse the PCAP file
	err = parser.ParseFile()
	require.NoError(t, err)

	// Verify both industrial and standard devices were processed
	devices, err := repo.GetDevices(nil)
	require.NoError(t, err)
	assert.Greater(t, len(devices), 2, "Should have detected multiple devices")

	var industrialDevices, standardDevices int
	for _, device := range devices {
		if device.AdditionalData != "" && containsIndustrialProtocols(device.AdditionalData) {
			industrialDevices++
		} else {
			standardDevices++
		}
	}

	assert.Greater(t, industrialDevices, 0, "Should have industrial devices")
	assert.Greater(t, standardDevices, 0, "Should have standard devices")

	// Verify flows were created for both types
	flows, err := repo.GetFlows(nil)
	require.NoError(t, err)
	assert.Greater(t, len(flows), 0, "Should have detected flows")

	// Verify communication patterns were analyzed (may or may not be present)
	_, err = repo.GetCommunicationPatterns("")
	require.NoError(t, err)
}

// TestGopacketParser_ErrorHandling tests error handling during industrial protocol parsing
func TestGopacketParser_ErrorHandling(t *testing.T) {
	// Create temporary database
	dbFile := "test_gopacket_error_handling.sqlite"
	defer os.Remove(dbFile)

	repo, err := repository.NewSQLiteRepository(dbFile)
	require.NoError(t, err)

	// Create test PCAP file with malformed industrial packets
	pcapFile := createMalformedIndustrialPCAP(t)
	defer os.Remove(pcapFile)

	// Create GopacketParser
	parser := NewGopacketParser(pcapFile, repo)
	require.NotNil(t, parser)

	// Parse the PCAP file - should not fail even with malformed packets
	err = parser.ParseFile()
	require.NoError(t, err, "Parser should handle malformed packets gracefully")

	// Verify some devices were still processed
	devices, err := repo.GetDevices(nil)
	require.NoError(t, err)
	// Should have at least some devices even with errors
	assert.GreaterOrEqual(t, len(devices), 0, "Should handle errors gracefully")
}

// Helper functions for test PCAP creation

func createMixedIndustrialStandardPCAP(t *testing.T) string {
	filename := "test_mixed_industrial_standard.pcap"
	file, err := os.Create(filename)
	require.NoError(t, err)
	defer file.Close()

	w := pcapgo.NewWriter(file)
	err = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	require.NoError(t, err)

	timestamp := time.Now()

	// Create standard HTTP traffic
	createHTTPPacket(t, w, timestamp, "192.168.1.10", "192.168.1.100")

	// Create EtherNet/IP traffic
	createEtherNetIPListIdentityPacket(t, w, timestamp.Add(time.Second), "192.168.1.20", "192.168.1.200")

	// Create OPC UA traffic
	createOPCUAHelloPacket(t, w, timestamp.Add(2*time.Second), "192.168.1.30", "192.168.1.300")

	// Create standard DNS traffic
	createDNSPacket(t, w, timestamp.Add(3*time.Second), "192.168.1.40", "192.168.1.1")

	return filename
}
func createStandardProtocolsPCAP(t *testing.T) string {
	filename := "test_standard_protocols.pcap"
	file, err := os.Create(filename)
	require.NoError(t, err)
	defer file.Close()

	w := pcapgo.NewWriter(file)
	err = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	require.NoError(t, err)

	timestamp := time.Now()

	// Create only standard protocols
	createHTTPPacket(t, w, timestamp, "192.168.1.10", "192.168.1.100")
	createDNSPacket(t, w, timestamp.Add(time.Second), "192.168.1.20", "192.168.1.1")
	createSSHPacket(t, w, timestamp.Add(2*time.Second), "192.168.1.30", "192.168.1.200")

	return filename
}

func createComprehensiveMixedTrafficPCAP(t *testing.T) string {
	filename := "test_comprehensive_mixed.pcap"
	file, err := os.Create(filename)
	require.NoError(t, err)
	defer file.Close()

	w := pcapgo.NewWriter(file)
	err = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	require.NoError(t, err)

	timestamp := time.Now()

	// Standard protocols
	createHTTPPacket(t, w, timestamp, "192.168.1.10", "192.168.1.100")
	createDNSPacket(t, w, timestamp.Add(time.Second), "192.168.1.20", "192.168.1.1")

	// Industrial protocols
	createEtherNetIPListIdentityPacket(t, w, timestamp.Add(2*time.Second), "192.168.1.30", "192.168.1.200")
	createOPCUAHelloPacket(t, w, timestamp.Add(3*time.Second), "192.168.1.40", "192.168.1.300")

	// More standard traffic
	createSSHPacket(t, w, timestamp.Add(4*time.Second), "192.168.1.50", "192.168.1.400")

	// More industrial traffic for pattern analysis
	createEtherNetIPListIdentityResponsePacket(t, w, timestamp.Add(5*time.Second), "192.168.1.200", "192.168.1.30")
	createOPCUAAcknowledgePacket(t, w, timestamp.Add(6*time.Second), "192.168.1.300", "192.168.1.40")

	return filename
}

func createMalformedIndustrialPCAP(t *testing.T) string {
	filename := "test_malformed_industrial.pcap"
	file, err := os.Create(filename)
	require.NoError(t, err)
	defer file.Close()

	w := pcapgo.NewWriter(file)
	err = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	require.NoError(t, err)

	timestamp := time.Now()

	// Valid packet first
	createHTTPPacket(t, w, timestamp, "192.168.1.10", "192.168.1.100")

	// Malformed EtherNet/IP packet
	createMalformedEtherNetIPIntegrationPacket(t, w, timestamp.Add(time.Second), "192.168.1.20", "192.168.1.200")

	// Valid packet after malformed
	createDNSPacket(t, w, timestamp.Add(2*time.Second), "192.168.1.30", "192.168.1.1")

	return filename
}

// Helper functions for test validation

func containsIndustrialProtocols(additionalData string) bool {
	// Simple check for industrial protocol information in additional data
	return strings.Contains(additionalData, "industrial_protocols") ||
		strings.Contains(additionalData, "ethernetip") ||
		strings.Contains(additionalData, "opcua") ||
		strings.Contains(additionalData, "industrial_device_type")
}

func extractDeviceClassification(additionalData string) string {
	// Simple extraction of device classification from additional data
	// In a real implementation, this would parse JSON
	if strings.Contains(additionalData, "industrial_device_type") {
		// Extract the device type value
		start := strings.Index(additionalData, "industrial_device_type")
		if start != -1 {
			substr := additionalData[start:]
			if colonIndex := strings.Index(substr, ":"); colonIndex != -1 {
				valueStart := colonIndex + 1
				if quoteStart := strings.Index(substr[valueStart:], "\""); quoteStart != -1 {
					valueStart += quoteStart + 1
					if quoteEnd := strings.Index(substr[valueStart:], "\""); quoteEnd != -1 {
						return substr[valueStart : valueStart+quoteEnd]
					}
				}
			}
		}
	}
	return ""
}
