package parser

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndustrialProtocolParserImpl_CollectProtocolUsageStats(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)
	now := time.Now()

	tests := []struct {
		name          string
		deviceAddress string
		protocols     []IndustrialProtocolInfo
		want          *model.ProtocolUsageStats
		wantErr       bool
	}{
		{
			name:          "empty protocols",
			deviceAddress: "192.168.1.100",
			protocols:     []IndustrialProtocolInfo{},
			want:          nil,
			wantErr:       false,
		},
		{
			name:          "single EtherNet/IP protocol",
			deviceAddress: "192.168.1.100",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:        "ethernetip",
					Port:            44818,
					Direction:       "outbound",
					IsRealTimeData:  true,
					IsDiscovery:     false,
					IsConfiguration: false,
					Confidence:      0.9,
					Timestamp:       now,
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       1,
				ByteCount:         96, // 64 + 32 for real-time data
				FirstSeen:         now,
				LastSeen:          now,
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			wantErr: false,
		},
		{
			name:          "single OPC UA protocol",
			deviceAddress: "192.168.1.101",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:        "opcua",
					Port:            4840,
					Direction:       "inbound",
					IsRealTimeData:  false,
					IsDiscovery:     true,
					IsConfiguration: false,
					Confidence:      0.95,
					Timestamp:       now,
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.101",
				Protocol:          "opcua",
				PacketCount:       1,
				ByteCount:         576, // 64 + 512 for discovery
				FirstSeen:         now,
				LastSeen:          now,
				CommunicationRole: "server",
				PortsUsed:         []uint16{4840},
			},
			wantErr: false,
		},
		{
			name:          "multiple protocols same type",
			deviceAddress: "192.168.1.102",
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:        "ethernetip",
					Port:            44818,
					Direction:       "outbound",
					IsRealTimeData:  true,
					IsDiscovery:     false,
					IsConfiguration: false,
					Confidence:      0.9,
					Timestamp:       now,
				},
				{
					Protocol:        "ethernetip",
					Port:            2222,
					Direction:       "inbound",
					IsRealTimeData:  false,
					IsDiscovery:     false,
					IsConfiguration: true,
					Confidence:      0.85,
					Timestamp:       now.Add(time.Second),
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.102",
				Protocol:          "ethernetip",
				PacketCount:       2,
				ByteCount:         416, // (64+32) + (64+256) for real-time + config
				FirstSeen:         now,
				LastSeen:          now.Add(time.Second),
				CommunicationRole: "both", // client + server = both
				PortsUsed:         []uint16{44818, 2222},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.CollectProtocolUsageStats(tt.deviceAddress, tt.protocols)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tt.want == nil {
				assert.Nil(t, got)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, tt.want.DeviceID, got.DeviceID)
			assert.Equal(t, tt.want.Protocol, got.Protocol)
			assert.Equal(t, tt.want.PacketCount, got.PacketCount)
			assert.Equal(t, tt.want.ByteCount, got.ByteCount)
			assert.Equal(t, tt.want.CommunicationRole, got.CommunicationRole)
			assert.ElementsMatch(t, tt.want.PortsUsed, got.PortsUsed)
			assert.True(t, tt.want.FirstSeen.Equal(got.FirstSeen))
			assert.True(t, tt.want.LastSeen.Equal(got.LastSeen))
		})
	}
}

func TestIndustrialProtocolParserImpl_UpdateProtocolUsageStats(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)
	now := time.Now()
	later := now.Add(time.Hour)

	tests := []struct {
		name      string
		existing  *model.ProtocolUsageStats
		protocols []IndustrialProtocolInfo
		want      *model.ProtocolUsageStats
		wantErr   bool
	}{
		{
			name:      "nil existing stats",
			existing:  nil,
			protocols: []IndustrialProtocolInfo{},
			want:      nil,
			wantErr:   true,
		},
		{
			name: "update with matching protocol",
			existing: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       5,
				ByteCount:         1000,
				FirstSeen:         now,
				LastSeen:          now.Add(time.Minute),
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:        "ethernetip",
					Port:            2222,
					Direction:       "inbound",
					IsRealTimeData:  false,
					IsDiscovery:     false,
					IsConfiguration: true,
					Confidence:      0.9,
					Timestamp:       later,
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       6,
				ByteCount:         1320, // 1000 + (64+256)
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "both", // client + server = both
				PortsUsed:         []uint16{44818, 2222},
			},
			wantErr: false,
		},
		{
			name: "update with non-matching protocol",
			existing: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       5,
				ByteCount:         1000,
				FirstSeen:         now,
				LastSeen:          now.Add(time.Minute),
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:        "opcua",
					Port:            4840,
					Direction:       "outbound",
					IsRealTimeData:  false,
					IsDiscovery:     true,
					IsConfiguration: false,
					Confidence:      0.95,
					Timestamp:       later,
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       5,
				ByteCount:         1000,
				FirstSeen:         now,
				LastSeen:          now.Add(time.Minute),
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			wantErr: false,
		},
		{
			name: "update with earlier timestamp",
			existing: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       5,
				ByteCount:         1000,
				FirstSeen:         now.Add(time.Hour),
				LastSeen:          now.Add(time.Hour * 2),
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			protocols: []IndustrialProtocolInfo{
				{
					Protocol:        "ethernetip",
					Port:            44818,
					Direction:       "outbound",
					IsRealTimeData:  true,
					IsDiscovery:     false,
					IsConfiguration: false,
					Confidence:      0.9,
					Timestamp:       now, // Earlier than existing FirstSeen
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       6,
				ByteCount:         1096, // 1000 + (64+32)
				FirstSeen:         now,  // Updated to earlier time
				LastSeen:          now.Add(time.Hour * 2),
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.UpdateProtocolUsageStats(tt.existing, tt.protocols)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tt.want == nil {
				assert.Nil(t, got)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, tt.want.DeviceID, got.DeviceID)
			assert.Equal(t, tt.want.Protocol, got.Protocol)
			assert.Equal(t, tt.want.PacketCount, got.PacketCount)
			assert.Equal(t, tt.want.ByteCount, got.ByteCount)
			assert.Equal(t, tt.want.CommunicationRole, got.CommunicationRole)
			assert.ElementsMatch(t, tt.want.PortsUsed, got.PortsUsed)
			assert.True(t, tt.want.FirstSeen.Equal(got.FirstSeen))
			assert.True(t, tt.want.LastSeen.Equal(got.LastSeen))
		})
	}
}

func TestIndustrialProtocolParserImpl_AggregateProtocolUsageStats(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)
	now := time.Now()

	tests := []struct {
		name      string
		statsList []*model.ProtocolUsageStats
		want      *model.ProtocolUsageStats
		wantErr   bool
	}{
		{
			name:      "empty stats list",
			statsList: []*model.ProtocolUsageStats{},
			want:      nil,
			wantErr:   false,
		},
		{
			name: "single stats",
			statsList: []*model.ProtocolUsageStats{
				{
					DeviceID:          "192.168.1.100",
					Protocol:          "ethernetip",
					PacketCount:       10,
					ByteCount:         2000,
					FirstSeen:         now,
					LastSeen:          now.Add(time.Minute),
					CommunicationRole: "client",
					PortsUsed:         []uint16{44818},
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       10,
				ByteCount:         2000,
				FirstSeen:         now,
				LastSeen:          now.Add(time.Minute),
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			wantErr: false,
		},
		{
			name: "aggregate same device and protocol",
			statsList: []*model.ProtocolUsageStats{
				{
					DeviceID:          "192.168.1.100",
					Protocol:          "ethernetip",
					PacketCount:       10,
					ByteCount:         2000,
					FirstSeen:         now,
					LastSeen:          now.Add(time.Minute),
					CommunicationRole: "client",
					PortsUsed:         []uint16{44818},
				},
				{
					DeviceID:          "192.168.1.100",
					Protocol:          "ethernetip",
					PacketCount:       5,
					ByteCount:         1000,
					FirstSeen:         now.Add(time.Minute * 2),
					LastSeen:          now.Add(time.Minute * 3),
					CommunicationRole: "server",
					PortsUsed:         []uint16{2222},
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       15,
				ByteCount:         3000,
				FirstSeen:         now,
				LastSeen:          now.Add(time.Minute * 3),
				CommunicationRole: "both", // client + server = both
				PortsUsed:         []uint16{44818, 2222},
			},
			wantErr: false,
		},
		{
			name: "aggregate with nil stats",
			statsList: []*model.ProtocolUsageStats{
				{
					DeviceID:          "192.168.1.100",
					Protocol:          "ethernetip",
					PacketCount:       10,
					ByteCount:         2000,
					FirstSeen:         now,
					LastSeen:          now.Add(time.Minute),
					CommunicationRole: "client",
					PortsUsed:         []uint16{44818},
				},
				nil,
				{
					DeviceID:          "192.168.1.100",
					Protocol:          "ethernetip",
					PacketCount:       5,
					ByteCount:         1000,
					FirstSeen:         now.Add(time.Minute * 2),
					LastSeen:          now.Add(time.Minute * 3),
					CommunicationRole: "client",
					PortsUsed:         []uint16{44818},
				},
			},
			want: &model.ProtocolUsageStats{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       15,
				ByteCount:         3000,
				FirstSeen:         now,
				LastSeen:          now.Add(time.Minute * 3),
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.AggregateProtocolUsageStats(tt.statsList)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tt.want == nil {
				assert.Nil(t, got)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, tt.want.DeviceID, got.DeviceID)
			assert.Equal(t, tt.want.Protocol, got.Protocol)
			assert.Equal(t, tt.want.PacketCount, got.PacketCount)
			assert.Equal(t, tt.want.ByteCount, got.ByteCount)
			assert.Equal(t, tt.want.CommunicationRole, got.CommunicationRole)
			assert.ElementsMatch(t, tt.want.PortsUsed, got.PortsUsed)
			assert.True(t, tt.want.FirstSeen.Equal(got.FirstSeen))
			assert.True(t, tt.want.LastSeen.Equal(got.LastSeen))
		})
	}
}

func TestIndustrialProtocolParserImpl_DetermineCommunicationRole(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)

	tests := []struct {
		name     string
		protocol IndustrialProtocolInfo
		want     string
	}{
		{
			name: "outbound direction",
			protocol: IndustrialProtocolInfo{
				Direction: "outbound",
			},
			want: "client",
		},
		{
			name: "inbound direction",
			protocol: IndustrialProtocolInfo{
				Direction: "inbound",
			},
			want: "server",
		},
		{
			name: "bidirectional direction",
			protocol: IndustrialProtocolInfo{
				Direction: "bidirectional",
			},
			want: "both",
		},
		{
			name: "discovery protocol",
			protocol: IndustrialProtocolInfo{
				Direction:   "unknown",
				IsDiscovery: true,
			},
			want: "client",
		},
		{
			name: "service provider",
			protocol: IndustrialProtocolInfo{
				Direction:   "unknown",
				ServiceType: "read_service",
			},
			want: "server",
		},
		{
			name: "default case",
			protocol: IndustrialProtocolInfo{
				Direction: "unknown",
			},
			want: "client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.determineCommunicationRole(tt.protocol)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIndustrialProtocolParserImpl_EstimatePacketSize(t *testing.T) {
	parser := NewIndustrialProtocolParser().(*IndustrialProtocolParserImpl)

	tests := []struct {
		name     string
		protocol IndustrialProtocolInfo
		want     int64
	}{
		{
			name: "EtherNet/IP real-time data",
			protocol: IndustrialProtocolInfo{
				Protocol:       "ethernetip",
				IsRealTimeData: true,
			},
			want: 96, // 64 + 32
		},
		{
			name: "EtherNet/IP configuration",
			protocol: IndustrialProtocolInfo{
				Protocol:        "ethernetip",
				IsConfiguration: true,
			},
			want: 320, // 64 + 256
		},
		{
			name: "EtherNet/IP default",
			protocol: IndustrialProtocolInfo{
				Protocol: "ethernetip",
			},
			want: 192, // 64 + 128
		},
		{
			name: "OPC UA discovery",
			protocol: IndustrialProtocolInfo{
				Protocol:    "opcua",
				IsDiscovery: true,
			},
			want: 576, // 64 + 512
		},
		{
			name: "OPC UA real-time data",
			protocol: IndustrialProtocolInfo{
				Protocol:       "opcua",
				IsRealTimeData: true,
			},
			want: 128, // 64 + 64
		},
		{
			name: "OPC UA default",
			protocol: IndustrialProtocolInfo{
				Protocol: "opcua",
			},
			want: 320, // 64 + 256
		},
		{
			name: "unknown protocol",
			protocol: IndustrialProtocolInfo{
				Protocol: "modbus",
			},
			want: 128, // 64 + 64
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.estimatePacketSize(tt.protocol)
			assert.Equal(t, tt.want, got)
		})
	}
}
