package parser

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndustrialProtocolParserImpl_ParseIndustrialProtocols(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)

	tests := []struct {
		name           string
		packet         gopacket.Packet
		expectedCount  int
		expectedProtos []string
	}{
		{
			name:           "Empty packet",
			packet:         createEmptyPacket(),
			expectedCount:  0,
			expectedProtos: []string{},
		},
		{
			name:           "Non-industrial packet",
			packet:         createTestHTTPPacket(),
			expectedCount:  0,
			expectedProtos: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protocols, err := parser.ParseIndustrialProtocols(tt.packet)

			assert.NoError(t, err)
			assert.Len(t, protocols, tt.expectedCount)

			for i, expectedProto := range tt.expectedProtos {
				if i < len(protocols) {
					assert.Equal(t, expectedProto, protocols[i].Protocol)
				}
			}
		})
	}
}

func TestIndustrialProtocolParserImpl_DetectDeviceType(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)

	tests := []struct {
		name         string
		protocols    []model.IndustrialProtocolInfo
		flows        []model.Flow
		expectedType model.IndustrialDeviceType
	}{
		{
			name:         "No protocols",
			protocols:    []IndustrialProtocolInfo{},
			flows:        []model.Flow{},
			expectedType: model.DeviceTypeUnknown,
		},
		{
			name: "PLC with EtherNet/IP",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:       "EtherNet/IP",
					Port:           44818,
					Direction:      "inbound",
					ServiceType:    "server",
					IsRealTimeData: true,
					Confidence:     0.9,
				},
			},
			flows: []model.Flow{
				{
					Source:      "192.168.1.100",
					Destination: "192.168.1.10",
					Protocol:    "EtherNet/IP",
					Bytes:       1024,
				},
			},
			expectedType: model.DeviceTypePLC,
		},
		{
			name: "HMI with OPC UA client",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:        "OPC UA",
					Port:            4840,
					Direction:       "outbound",
					ServiceType:     "client",
					IsConfiguration: true,
					Confidence:      0.9,
				},
			},
			flows: []model.Flow{
				{
					Source:      "192.168.1.20",
					Destination: "192.168.1.100",
					Protocol:    "OPC UA",
					Bytes:       512,
				},
			},
			expectedType: model.DeviceTypeHMI,
		},
		{
			name: "I/O Device with Modbus",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:       "Modbus TCP",
					Port:           502,
					Direction:      "inbound",
					ServiceType:    "server",
					IsRealTimeData: true,
					Confidence:     0.8,
				},
			},
			flows: []model.Flow{
				{
					Source:      "192.168.1.30",
					Destination: "192.168.1.100",
					Protocol:    "Modbus TCP",
					Bytes:       256,
				},
			},
			expectedType: model.DeviceTypeIODevice,
		},
		{
			name: "Engineering Workstation with multiple protocols",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:        "EtherNet/IP",
					Port:            44818,
					Direction:       "bidirectional",
					IsConfiguration: true,
					IsDiscovery:     true,
					Confidence:      0.9,
				},
				{
					Protocol:        "OPC UA",
					Port:            4840,
					Direction:       "bidirectional",
					IsConfiguration: true,
					IsDiscovery:     true,
					Confidence:      0.9,
				},
			},
			flows: []model.Flow{
				{
					Source:      "192.168.1.50",
					Destination: "192.168.1.100",
					Protocol:    "EtherNet/IP",
					Bytes:       2048,
				},
			},
			expectedType: model.DeviceTypeEngWorkstation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceType := parser.DetectDeviceType(tt.protocols, tt.flows)
			assert.Equal(t, tt.expectedType, deviceType)
		})
	}
}

func TestIndustrialProtocolParserImpl_AnalyzeCommunicationPatterns(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)

	tests := []struct {
		name            string
		flows           []model.Flow
		expectedCount   int
		expectedPattern string
	}{
		{
			name:            "No flows",
			flows:           []model.Flow{},
			expectedCount:   0,
			expectedPattern: "",
		},
		{
			name: "Single flow - event driven",
			flows: []model.Flow{
				{
					Source:      "192.168.1.10",
					Destination: "192.168.1.100",
					Protocol:    "EtherNet/IP",
					Bytes:       1024,
					FirstSeen:   time.Now().Add(-time.Hour),
					LastSeen:    time.Now(),
				},
			},
			expectedCount:   1,
			expectedPattern: "event-driven",
		},
		{
			name: "Multiple flows - periodic",
			flows: []model.Flow{
				{
					Source:      "192.168.1.10",
					Destination: "192.168.1.100",
					Protocol:    "EtherNet/IP",
					Bytes:       1024,
					FirstSeen:   time.Now().Add(-time.Hour),
					LastSeen:    time.Now().Add(-50 * time.Minute),
				},
				{
					Source:      "192.168.1.10",
					Destination: "192.168.1.100",
					Protocol:    "EtherNet/IP",
					Bytes:       1024,
					FirstSeen:   time.Now().Add(-40 * time.Minute),
					LastSeen:    time.Now().Add(-30 * time.Minute),
				},
				{
					Source:      "192.168.1.10",
					Destination: "192.168.1.100",
					Protocol:    "EtherNet/IP",
					Bytes:       1024,
					FirstSeen:   time.Now().Add(-20 * time.Minute),
					LastSeen:    time.Now().Add(-10 * time.Minute),
				},
				{
					Source:      "192.168.1.10",
					Destination: "192.168.1.100",
					Protocol:    "EtherNet/IP",
					Bytes:       1024,
					FirstSeen:   time.Now().Add(-10 * time.Minute),
					LastSeen:    time.Now(),
				},
				{
					Source:      "192.168.1.10",
					Destination: "192.168.1.100",
					Protocol:    "EtherNet/IP",
					Bytes:       1024,
					FirstSeen:   time.Now().Add(-5 * time.Minute),
					LastSeen:    time.Now(),
				},
				{
					Source:      "192.168.1.10",
					Destination: "192.168.1.100",
					Protocol:    "EtherNet/IP",
					Bytes:       1024,
					FirstSeen:   time.Now().Add(-2 * time.Minute),
					LastSeen:    time.Now(),
				},
			},
			expectedCount:   1,
			expectedPattern: "periodic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patterns := parser.AnalyzeCommunicationPatterns(tt.flows)
			assert.Len(t, patterns, tt.expectedCount)

			if tt.expectedCount > 0 && len(patterns) > 0 {
				assert.Equal(t, tt.expectedPattern, patterns[0].PatternType)
			}
		})
	}
}

func TestIndustrialProtocolParserImpl_CollectProtocolUsageStats(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)

	tests := []struct {
		name        string
		deviceID    string
		protocols   []IndustrialProtocolInfo
		expectStats bool
		expectError bool
	}{
		{
			name:        "No protocols",
			deviceID:    "192.168.1.100",
			protocols:   []IndustrialProtocolInfo{},
			expectStats: false,
			expectError: false,
		},
		{
			name:     "Single protocol",
			deviceID: "192.168.1.100",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:  "EtherNet/IP",
					Port:      44818,
					Direction: "inbound",
					Timestamp: time.Now(),
				},
			},
			expectStats: true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats, err := parser.CollectProtocolUsageStats(tt.deviceID, tt.protocols)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.expectStats {
				require.NotNil(t, stats)
				assert.Equal(t, tt.deviceID, stats.DeviceID)
				if len(tt.protocols) > 0 {
					assert.Equal(t, tt.protocols[0].Protocol, stats.Protocol)
				}
			} else {
				assert.Nil(t, stats)
			}
		})
	}
}

func TestIndustrialProtocolParserImpl_DetermineCriticality(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)

	tests := []struct {
		name                string
		protocol            string
		dataVolume          int64
		flowCount           int
		expectedCriticality string
	}{
		{
			name:                "EtherNet/IP high volume",
			protocol:            "EtherNet/IP",
			dataVolume:          15000,
			flowCount:           25,
			expectedCriticality: "critical",
		},
		{
			name:                "EtherNet/IP normal volume",
			protocol:            "EtherNet/IP",
			dataVolume:          5000,
			flowCount:           10,
			expectedCriticality: "high",
		},
		{
			name:                "OPC UA high volume",
			protocol:            "OPC UA",
			dataVolume:          60000,
			flowCount:           60,
			expectedCriticality: "high",
		},
		{
			name:                "OPC UA normal volume",
			protocol:            "OPC UA",
			dataVolume:          30000,
			flowCount:           30,
			expectedCriticality: "medium",
		},
		{
			name:                "Unknown protocol high volume",
			protocol:            "Unknown",
			dataVolume:          150000,
			flowCount:           100,
			expectedCriticality: "medium",
		},
		{
			name:                "Unknown protocol low volume",
			protocol:            "Unknown",
			dataVolume:          1000,
			flowCount:           5,
			expectedCriticality: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criticality := parser.DetermineCriticality(tt.protocol, tt.dataVolume, tt.flowCount)
			assert.Equal(t, tt.expectedCriticality, criticality)
		})
	}
}

func TestIndustrialProtocolParserImpl_DeterminePatternType(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)

	tests := []struct {
		name            string
		flows           []model.Flow
		expectedPattern string
	}{
		{
			name: "Single flow",
			flows: []model.Flow{
				{
					Source:      "192.168.1.10",
					Destination: "192.168.1.100",
					FirstSeen:   time.Now().Add(-time.Hour),
					LastSeen:    time.Now(),
				},
			},
			expectedPattern: "event-driven",
		},
		{
			name:            "Multiple flows - periodic",
			flows:           createMultipleFlows(6, time.Minute*10),
			expectedPattern: "periodic",
		},
		{
			name:            "Many flows - continuous",
			flows:           createMultipleFlows(15, time.Minute*5),
			expectedPattern: "continuous",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := parser.DeterminePatternType(tt.flows)
			assert.Equal(t, tt.expectedPattern, pattern)
		})
	}
}

// Helper functions for creating test data

func createEmptyPacket() gopacket.Packet {
	// Create a minimal packet with just metadata
	return gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)
}

func createTestHTTPPacket() gopacket.Packet {
	// Create a simple HTTP packet for testing
	ethLayer := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{192, 168, 1, 100},
	}

	tcpLayer := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
	}

	// Serialize the layers
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	gopacket.SerializeLayers(buffer, opts, ethLayer, ipLayer, tcpLayer)

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func createMultipleFlows(count int, interval time.Duration) []model.Flow {
	flows := make([]model.Flow, count)
	baseTime := time.Now().Add(-time.Duration(count) * interval)

	for i := 0; i < count; i++ {
		flows[i] = model.Flow{
			Source:      "192.168.1.10",
			Destination: "192.168.1.100",
			Protocol:    "EtherNet/IP",
			Bytes:       1024,
			FirstSeen:   baseTime.Add(time.Duration(i) * interval),
			LastSeen:    baseTime.Add(time.Duration(i)*interval + time.Minute),
		}
	}

	return flows
}
